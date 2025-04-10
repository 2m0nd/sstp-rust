use std::{
    fs::File,
    io::{Read, Write},
    net::Ipv4Addr,
    os::fd::FromRawFd,
    os::unix::io::AsRawFd,
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

        // Открываем устройство /dev/net/tun
        let file = File::open("/dev/net/tun")?;
        let async_fd = AsyncFd::new(file)?;

        Ok(Self {
            inner: Arc::new(async_fd),
            read_buf: Arc::new(Mutex::new([0u8; 1504])),
            ifname,
        })
    }

    pub fn delete(ifname: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("🧹 Удаляем интерфейс {}", ifname);
        let status = Command::new("ip")
            .args(["tuntap", "del", "dev", ifname, "mode", "tun"])
            .status()?;

        if !status.success() {
            return Err(format!("Failed to delete TUN interface {}", ifname).into());
        }

        Ok(())
    }

    fn create_tun_interface() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let ifname = "tun0";

        // Проверяем: существует ли интерфейс
        let check = Command::new("ip")
            .args(["link", "show", "dev", ifname])
            .output()?;

        if check.status.success() {
            println!("⚠️ Интерфейс {} уже существует, удаляем...", ifname);
            let _ = Self::delete(ifname)?;
        }

        // Создаём заново
        let output = Command::new("ip")
            .args(["tuntap", "add", "mode", "tun", "name", ifname])
            .output()?;

        if !output.status.success() {
            return Err(format!(
                "Failed to create TUN interface: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }

        Ok(ifname.to_string())
    }

    fn setup_ip(
        ifname: &str,
        address: Ipv4Addr,
        _destination: Ipv4Addr,
        netmask: Ipv4Addr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cidr = mask_to_cidr(netmask)?;
        let status = Command::new("ip")
            .args([
                "addr",
                "add",
                &format!("{}/{}", address, cidr),
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

    pub fn restore_routes(
        &self,
        original_gateway: &str,
        vpn_server: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let iface = "enp0s1";
        // Удалить маршрут к VPN через основной интерфейс
        let _ = Command::new("ip")
            .args(["route", "del", &vpn_server.to_string()])
            .status();

        // Удалить default через туннель
        let _ = Command::new("ip")
            .args(["route", "del", "default"])
            .status();

        // Вернуть дефолт через основной шлюз
        let status = Command::new("ip")
            .args([
                "route",
                "add",
                "default",
                "via",
                &original_gateway.to_string(),
                "dev",
                iface,
            ])
            .status()?;

        if !status.success() {
            return Err("Failed to restore default route".into());
        }

        println!("✅ Default route восстановлен через {} ({})", iface, original_gateway);
        Ok(())
    }

    pub fn name(&self) -> &str {
        &self.ifname
    }
}

/// Преобразует netmask (например, 255.255.255.0) → CIDR (например, 24)
fn mask_to_cidr(mask: Ipv4Addr) -> Result<u8, Box<dyn std::error::Error + Send + Sync>> {
    let octets = mask.octets();
    let mut bits = 0;

    for byte in octets.iter() {
        match byte {
            255 => bits += 8,
            254 => bits += 7,
            252 => bits += 6,
            248 => bits += 5,
            240 => bits += 4,
            224 => bits += 3,
            192 => bits += 2,
            128 => bits += 1,
            0 => break,
            _ => return Err("Invalid netmask".into()),
        }
    }

    Ok(bits)
}
