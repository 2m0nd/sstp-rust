mod sstp;
mod ssl_verifiers;
use sstp::build_sstp_hello;
use ssl_verifiers::DisabledVerifier;

use std::sync::Arc;
use tokio::{net::TcpStream, io::{AsyncReadExt, AsyncWriteExt}};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{
    Certificate, ClientConfig, Error as TLSError, ServerName,
    client::ServerCertVerifier,
    client::ServerCertVerified,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_host = "SSTP_SERVER_IP_ADDRESS"; // IP или домен
    let addr = format!("{}:443", server_host);
    let domain = ServerName::try_from(server_host)?; // для SNI

    // 🔐 WARNING: отключаем проверку TLS-сертификатов
    let config = Arc::new(ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(DisabledVerifier))
        .with_no_client_auth());

    let connector = TlsConnector::from(config);
    let tcp = TcpStream::connect(addr).await?;
    let mut stream = connector.connect(domain, tcp).await?;

    println!("✅ TLS подключение установлено.");

    // Простейший SSTP Hello-заглушка
    let hello = vec![0x10, 0x01, 0x00, 0x10];
    stream.write_all(&hello).await?;
    println!("📨 Отправлен SSTP Hello");

    let mut buf = vec![0; 4096];
    let n = stream.read(&mut buf).await?;
    println!("📥 Ответ от сервера ({} байт):", n);
    println!("{:02X?}", &buf[..n]);

    Ok(())
}