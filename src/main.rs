mod sstp;
mod parser;
mod ssl_verifiers;
use sstp::{
    wrap_lcp_packet,
    build_lcp_configure_ack,
    is_chap_challenge,
    is_lcp_configure_request,
    build_sstp_hello,
    parse_sstp_control_packet,
    parse_sstp_data_packet,
    build_lcp_configure_request,
    build_sstp_ppp_lcp_request,
    build_configure_ack_from_request,
    build_configure_nak_from_request,
    build_lcp_configure_request_fallback,
    build_lcp_configure_request_chap_simple,
    build_configure_ack
};
use ssl_verifiers::DisabledVerifier;
use uuid::Uuid;
use tokio::time::{sleep, Duration};

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
    let server_domain_name = "DNS_NAME_SSTP_SERVER";
    let _server_name = ServerName::try_from(server_domain_name)?;

    let domain = ServerName::IpAddress(server_ip.parse::<IpAddr>()?);

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(DisabledVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(&addr).await?;
    let mut stream = connector.connect(domain, tcp).await?;

    println!("✅ TLS подключение установлено");

    let correlation_id = Uuid::new_v4();
    let correlation_id_str = format!("{}", correlation_id).to_uppercase();
    let http_request = format!(
        "SSTP_DUPLEX_POST /sra_{{BA195980-CD49-458b-9E23-C84EE0ADCD75}}/ HTTP/1.1\r\n\
        Host: {host}\r\n\
        Content-Length: 18446744073709551615\r\n\
        SSTPCORRELATIONID: {{{corr_id}}}\r\n\
        \r\n",
        host = server_ip,
        corr_id = correlation_id_str
    );

    stream.write_all(http_request.as_bytes()).await?;
    println!("📨 Отправлен SSTP HTTP POST");
    println!("📥 Отправлен:\n{}", http_request);

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);
    println!("📥 HTTP ответ от сервера:\n{}", response);

    if !response.contains("200 OK") {
        println!("❌ Не удалось пройти SSTP INIT: сервер не ответил 200 OK");
        return Ok(());
    }

    let hello = sstp::build_sstp_hello(correlation_id);
    println!("📏 Hello длина: {} байт", hello.len());
    stream.write_all(&hello).await?;
    println!("📨 Отправлен SSTP Hello");

    let n = stream.read(&mut buf).await?;
    println!("📥 Ответ на Hello ({} байт): {:02X?}", n, &buf[..n]);


    let lcp_request = build_sstp_ppp_lcp_request();

    stream.write_all(&lcp_request).await?;
    println!("📨 Отправлен LCP Configure-Request ({} байт): {:02X?}", lcp_request.len(), &lcp_request);

    let mut counter = 0;
    //читаем ответы на подключение по ppp
    loop {
        counter += 1;
        println!("📡 Ждём пакеты от сервера...");
        let n = stream.read(&mut buf).await?;
        println!("[{}] 📥 Получено ({} байт): {:02X?}", counter, n, &buf[..n]);

        if let Some(ppp) = parse_sstp_data_packet(&buf[..n]) {
            if ppp.protocol == 0xC021 && ppp.code == 0x01 {
                println!("🔧 Получен LCP Configure-Request от сервера (ID = {})", ppp.id);

                // 👉 Формируем Configure-Ack с теми же опциями, что пришли
                let ack = build_lcp_configure_ack(ppp.id, &ppp.payload);

                // Оборачиваем в PPP + SSTP и отправляем
                let packet = wrap_lcp_packet(0x02, ppp.id, &ack); // Code 0x02 = Configure-Ack
                stream.write_all(&packet).await?;
                println!("✅ Отправлен Configure-Ack на LCP ({} байт): {:02X?}", 
                        packet.len(), &packet[..packet.len()]);
            }
        }
    }



    Ok(())
}