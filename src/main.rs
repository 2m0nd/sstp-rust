mod sstp;
mod ssl_verifiers;
use sstp::build_sstp_hello;
use ssl_verifiers::DisabledVerifier;
use uuid::Uuid;

use std::time::Duration;
use std::net::IpAddr;
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
    let server_ip = "SSTP_SERVER_IP_ADDRESS";
    let addr = format!("{server_ip}:443");
    
    let domainName = ServerName::try_from("DNS_NAME_SSTP_SERVER")?;

    // ⚠️ Важно: используем IP, чтобы не отправлять SNI
    let domain = ServerName::IpAddress(server_ip.parse::<IpAddr>()?);

    // TLS без проверки сертификатов (для тестов)
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(DisabledVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(&addr).await?;
    let mut stream = connector.connect(domain, tcp).await?;

    println!("✅ TLS подключение установлено");

    // === 1. Отправляем SSTP INIT HTTP-запрос ===
    let correlation_id = Uuid::new_v4();
    let http_request = format!(
        "SSTP_DUPLEX_POST /sra_{{BA195980-CD49-458b-9E23-C84EE0ADCD75}}/ HTTP/1.1\r\n\
Host: {host}\r\n\
Content-Length: 18446744073709551615\r\n\
SSTPCORRELATIONID: {{{corr_id}}}\r\n\
\r\n",
        host = server_ip,
        corr_id = correlation_id
    );

    stream.write_all(http_request.as_bytes()).await?;
    println!("📨 Отправлен SSTP HTTP POST");
    println!("📥 Отправлен:\n{}", http_request);

    // === 2. Читаем HTTP-ответ от сервера ===
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);
    println!("📥 HTTP ответ от сервера:\n{}", response);

    if !response.contains("200 OK") {
        println!("❌ Не удалось пройти SSTP INIT: сервер не ответил 200 OK");
        return Ok(());
    }

    // //подождем перед hello
    // tokio::time::sleep(Duration::from_millis(2000)).await;

    // === 3. Отправляем SSTP Hello ===
    let hello = sstp::build_sstp_hello(correlation_id);
    println!("📏 Hello длина: {} байт", hello.len());
    stream.write_all(&hello).await?;
    println!("📨 Отправлен SSTP Hello");

    // //подождем перед чтением
    // tokio::time::sleep(Duration::from_millis(2000)).await;

    // === 4. Читаем ответ от сервера (SSTP Connect Ack или NAK) ===
    let n = stream.read(&mut buf).await?;
    println!("📥 Ответ на Hello ({} байт): {:02X?}", n, &buf[..n]);

    // === 5. Разбираем заголовок SSTP ===
    if n >= 6 && buf[0] == 0x10 && buf[1] == 0x01 {
        let length = u16::from_be_bytes([buf[2], buf[3]]);
        let message_type = u16::from_be_bytes([buf[4], buf[5]]);
        println!("🧩 SSTP Message: длина = {}, тип = 0x{:04X}", length, message_type);

        match message_type {
            0x0002 => println!("✅ Получен Call Connect ACK — сервер принял SSTP Hello!"),
            0x0003 => println!("❌ Получен Call Connect NAK — сервер отклонил SSTP Hello"),
            0x0005 => println!("⛔ Получен Call Disconnect — сервер сбросил соединение"),
            other => println!("❓ Неизвестный тип сообщения: 0x{:04X}", other),
        }
    } else {
        println!("⚠️ Ответ не похож на SSTP Control Packet.");
    }

    Ok(())
}