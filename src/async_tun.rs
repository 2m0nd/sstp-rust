use std::{
    fs::File,
    io::{Read, Write},
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd},
    process::Command,
    sync::Arc,
};

use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;

use nix::libc::{sockaddr_ctl, ctl_info, AF_SYSTEM, AF_SYS_CONTROL, SYSPROTO_CONTROL};

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
        println!("🚀 AsyncTun::new() — старт");

        Self::config_routes(vpn_server);

        let raw_fd = unsafe {
            libc::socket(AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL)
        };

        if raw_fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        println!("📦 Сокет создан: fd = {}", raw_fd);

        let mut info = ctl_info {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        let name = b"com.apple.net.utun_control\0";
        for (dst, src) in info.ctl_name.iter_mut().zip(name.iter()) {
            *dst = *src as i8;
        }

        println!("📞 Отправляем ioctl...");

        if unsafe { libc::ioctl(raw_fd, libc::CTLIOCGINFO, &mut info) } < 0 {
            println!("❌ ioctl CTLIOCGINFO failed");
            unsafe { libc::close(raw_fd) };
            return Err("ioctl CTLIOCGINFO failed".into());
        }

        println!("✅ ioctl CTLIOCGINFO success, ctl_id = {}", info.ctl_id);

        let mut addr = sockaddr_ctl {
            sc_len: std::mem::size_of::<sockaddr_ctl>() as u8,
            sc_family: AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };

        let addr_ptr = &addr as *const sockaddr_ctl as *const libc::sockaddr;
        let addr_len = std::mem::size_of::<sockaddr_ctl>() as libc::socklen_t;

        println!("🔌 Пытаемся подключиться к утилите...");
        let res = unsafe { libc::connect(raw_fd, addr_ptr, addr_len) };
        if res < 0 {
            println!("❌ connect() to utun_control failed: {}", std::io::Error::last_os_error());
            unsafe { libc::close(raw_fd) };
            return Err("connect() to utun control failed".into());
        }
        println!("✅ connect() OK, интерфейс поднят");

        //Self::add_default_route("tnu");

        let mut name_buf = [0u8; 128];
        let mut name_len = name_buf.len() as u32;

        let ret = unsafe {
            libc::getsockopt(
                raw_fd,
                SYSPROTO_CONTROL,
                2,
                name_buf.as_mut_ptr() as *mut _,
                &mut name_len,
            )
        };

        let ifname = if ret < 0 {
            println!("❌ getsockopt(UTUN_OPT_IFNAME) failed: {}", std::io::Error::last_os_error());
            "unknown".into()
        } else {
            String::from_utf8_lossy(&name_buf[..(name_len as usize - 1)]).to_string()
        };

        println!("🎉 Реально создан интерфейс: {}", ifname);

        // Назначаем IP, destination, netmask через ifconfig
        let status = Command::new("ifconfig")
            .args([
                &ifname,
                &address.to_string(),
                &destination.to_string(),
                "netmask",
                &netmask.to_string(),
                "up",
            ])
            .status()?;

        if !status.success() {
            return Err("ifconfig failed to configure utun".into());
        }

        let file = unsafe { File::from_raw_fd(raw_fd) };
        let async_fd = AsyncFd::new(file)?;

        println!("🎉 AsyncTun создан!");

        Self::add_default("utun9");

        Ok(Self {
            inner: Arc::new(async_fd),
            read_buf: Arc::new(Mutex::new([0u8; 1504])),
            ifname,
        })
    }

    fn config_routes(vpn_server: Ipv4Addr) -> Result<(), Box<dyn std::error::Error>>   {

         // добавить роут до vpn server'a чере маршрутизатор
         //sudo route add -host SSTP_SERVER_IP_ADDRESS 192.168.1.1
         let status = Command::new("route")
         .args([
            "add",
             "-host",
             &vpn_server.to_string(),
             "192.168.1.1"
         ])
         .status()?;
        if !status.success() {
            return Err("add route failed to configure utun".into());
        }
        //sudo route -n delete -net default
         let status = Command::new("route")
         .args([
            "-n",
             "delete",
             "-net",
             "default"
         ])
         .status()?;
        if !status.success() {
            return Err("error remove default route".into());
        }
        Ok(())
    }

    fn add_default(tun_name: &str) -> Result<(), Box<dyn std::error::Error>>   {

         // добавить дефолтный роут через наш интерфейс
         //sudo route -n add -net default -interface utun9
         let status = Command::new("route")
         .args([
             "-n",
             "add",
             "-net",
             "default",
             "-interface",
             tun_name,
         ])
         .status()?;
        if !status.success() {
            return Err("add route failed to configure utun".into());
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