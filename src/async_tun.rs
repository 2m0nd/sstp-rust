use std::{
    fs::File,
    io::{Read, Write},
    net::Ipv4Addr,
    os::unix::io::{AsRawFd, FromRawFd},
    sync::Arc,
};

use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;
use tun::{platform::Device as TunDevice, Configuration};

#[derive(Clone)]
pub struct AsyncTun {
    inner: Arc<AsyncFd<File>>,
    read_buf: Arc<Mutex<[u8; 1504]>>,
}

impl AsyncTun {
    pub fn new(
        address: Ipv4Addr,
        destination: Ipv4Addr,
        netmask: Ipv4Addr,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut config = Configuration::default();
        config
            .address(address)
            .destination(destination)
            .netmask(netmask)
            .up();

        let dev = TunDevice::new(&config).map_err(|e| {
            eprintln!("❌ Ошибка создания TUN: {e}");
            std::io::Error::new(std::io::ErrorKind::Other, e)
        })?;
        eprintln!("Созда TUN: {}", address);
        let raw_fd = dev.as_raw_fd();
        let file = unsafe { File::from_raw_fd(raw_fd) };
        let async_fd = AsyncFd::new(file)?;

        Ok(Self {
            inner: Arc::new(async_fd),
            read_buf: Arc::new(Mutex::new([0u8; 1504])),
        })
    }

    pub async fn read(&self) -> std::io::Result<Vec<u8>> {
        let mut guard = self.inner.readable().await?;
        let mut buf = self.read_buf.lock().await;

        match guard.try_io(|inner| {
            // &AsyncFd<File> → &File → File::read() не требует &mut
            inner.get_ref().read(&mut *buf)
        }) {
            Ok(Ok(n)) => Ok(buf[..n].to_vec()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "try_io would block",
            )),
        }
    }

    pub async fn write(&self, data: &[u8]) -> std::io::Result<()> {
        let mut guard = self.inner.writable().await?;

        match guard.try_io(|inner| {
            // &AsyncFd<File> → &File → File::write_all() тоже не требует &mut
            inner.get_ref().write_all(data)
        }) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "try_io would block",
            )),
        }
    }

    pub fn name(&self) -> &str {
        "utunX" // утилитарно, если хочешь — можно позже вытянуть реальное имя
    }
}
