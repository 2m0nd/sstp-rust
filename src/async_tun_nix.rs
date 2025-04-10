use std::{
    fs::File,
    io::{Read, Write},
    net::Ipv4Addr,
    os::fd::FromRawFd,
    process::Command,
    sync::Arc,
};

use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AsyncTun {
    inner: Arc<AsyncFd<File>>,
    read_buf: Arc<Mutex<[u8; 1504]>>,
    ifname: String,
}

impl AsyncTun {
    pub fn new(
        vpn_server: Ipv4Addr,
        address: Ipv4Addr,
        destination: Ipv4Addr,
        netmask: Ipv4Addr,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        println!("🚀 AsyncTun::new() for Debian");

        // Создаем TUN интерфейс
        let ifname = Self::create_tun_interface()?;
        println!("🎉 TUN интерфейс создан: {}", ifname);

        // Настраиваем IP-адрес
        Self::setup_ip(&ifname, address, destination, netmask)?;

        // Добавляем маршрут до VPN-сервера
        Self::add_route_to_server(&ifname, vpn_server)?;

        // Добавляем маршрут по умолчанию через TUN
        Self::add_default_route(&ifname)?;

        // Открываем файл устройства TUN
        let file = File::open(format!("/dev/net/{}", ifname))?;
        let async_fd = AsyncFd::new(file)?;

        Ok(Self {
            inner: Arc::new(async_fd),
            read_buf: Arc::new(Mutex::new([0u8; 1504])),
            ifname,
        })
    }

    fn create_tun_interface() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let output = Command::new("ip")
            .args(["tuntap", "add", "mode", "tun", "name", "tun0"])
            .output()?;

        if !output.status.success() {
            return Err(format!(
                "Failed to create TUN interface: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }

        Ok("tun0".to_string())
    }

    fn setup_ip(
        ifname: &str,
        address: Ipv4Addr,
        destination: Ipv4Addr,
        netmask: Ipv4Addr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let status = Command::new("ip")
            .args([
                "addr",
                "add",
                &format!("{}/{}", address, netmask),
                "dev",
                ifname,
            ])
            .status()?;

        if !status.success() {
            return Err("Failed to configure IP address for TUN interface".into());
        }

        let status = Command::new("ip")
            .args(["link", "set", "dev", ifname, "up"])
            .status()?;

        if !status.success() {
            return Err("Failed to bring up TUN interface".into());
        }

        Ok(())
    }

    fn add_route_to_server(
        ifname: &str,
        vpn_server: Ipv4Addr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let status = Command::new("ip")
            .args([
                "route",
                "add",
                &vpn_server.to_string(),
                "dev",
                ifname,
            ])
            .status()?;

        if !status.success() {
            return Err("Failed to add route to VPN server".into());
        }

        Ok(())
    }

    fn add_default_route(ifname: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let status = Command::new("ip")
            .args(["route", "add", "default", "dev", ifname])
            .status()?;

        if !status.success() {
            return Err("Failed to add default route through TUN interface".into());
        }

        Ok(())
    }

    pub async fn read(&self) -> std::io::Result<Vec<u8>> {
        let mut guard = self.inner.readable().await?;
        let mut buf = self.read_buf.lock().await;

        match guard.try_io(|inner| inner.get_ref().read(&mut *buf)) {
            Ok(Ok(n)) => Ok(buf[..n].to_vec()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "try_io would block")),
        }
    }

    pub async fn write(&self, data: &[u8]) -> std::io::Result<()> {
        let mut guard = self.inner.writable().await?;

        match guard.try_io(|inner| inner.get_ref().write_all(data)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "try_io would block")),
        }
    }

    pub fn name(&self) -> &str {
        &self.ifname
    }
}