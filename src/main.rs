mod sstp;
mod parser;
mod ssl_verifiers;
use crate::sstp::*;
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

    println!("📡 Ждём пакеты от сервера...");
    let n = stream.read(&mut buf).await?;
    println!("📥 Получено ({} байт): {:02X?}", n, &buf[..n]);

    if let Some(ppp) = parse_sstp_data_packet(&buf[..n]) {
        if ppp.protocol == 0xC021 && ppp.code == 0x01 {
            println!("🔧 Получен LCP Configure-Request от сервера (ID = {})", ppp.id);
            let ack_packet = build_sstp_packet_from_ppp(0x02, &ppp); // Configure-Ack
            stream.write_all(&ack_packet).await?;
            let ack_len = ack_packet.len();
            println!("✅ Отправлен Configure-Ack на LCP ({} байт): {:02X?}", 
                    ack_len, &ack_packet[..ack_len]);

            //сразу стартуем авторизацию
            let auth_pack = wrap_ppp_pap_packet(1, "AHC\\test_user_client", "EXAPLME_PWD");
            let auth_pack_len = auth_pack.len();
            stream.write_all(&auth_pack).await?;
            println!("✅ auth pack ({} байт): {:02X?}", 
                    auth_pack_len, &auth_pack[..auth_pack_len]);

            
            println!("📡 Ждём пакеты от сервера...");
            let n = stream.read(&mut buf).await?;
            println!("📥 Получено ({} байт): {:02X?}", n, &buf[..n]);
            if let Some(ppp) = parse_sstp_data_packet(&buf[..n]) {

                let ipcp_packet = build_ipcp_configure_request_packet(1);
                println!("✅ ipcp req ({} байт): {:02X?}", 
                    auth_pack_len, &auth_pack[..auth_pack_len]);
                stream.write_all(&ipcp_packet).await?;
                let n = stream.read(&mut buf).await?;
                println!("📥 Получено ({} байт): {:02X?}", n, &buf[..n]);
                if let Some(ppp) = parse_sstp_data_packet(&buf[..n]) {
                }
            }
        }
    }



    Ok(())
}