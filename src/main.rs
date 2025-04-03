mod sstp;
mod parser;
mod ssl_verifiers;
use crate::sstp::*;
use crate::parser::*;
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

#[derive(Debug)]
enum PppState {
    SendLcpRequest,
    WaitLcpRequest,
    SendLcpAck,
    SendPapAuth,
    WaitPapAck,
    SendIpcpRequest,
    WaitIpcpRequest,
    SendIpcpAck,
    Done,
    WaitIpcpResponse,
    SendIpcpCustomRequest,
    WaitIpcpNakWithOffer,
    WaitIpcpFinalAck,
    Error(String),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let user = "AHC\\test_user_client";
    let pwd = "EXAPLME_PWD";
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

    let mut buf = [0u8; 1500];
    let mut state = PppState::SendLcpRequest;
    let mut id_counter: u8 = 1;

    loop {
        let ppp = match state {
            PppState::WaitIpcpNakWithOffer |
            PppState::WaitLcpRequest |
            PppState::WaitPapAck |
            PppState::WaitIpcpFinalAck |
            PppState::WaitIpcpRequest => {
                println!("📡 Ожидание пакета...");
                match read_and_parse(&mut stream, &mut buf).await {
                    Some(ppp) => Some(ppp),
                    None => {
                        eprintln!("❌ Ошибка чтения/парсинга пакета");
                        state = PppState::Error("Парсинг не удался".into());
                        None
                    }
                }
            }
            _ => None,
        };

        match state {
            
            PppState::SendLcpAck |
            PppState::WaitIpcpResponse |
             PppState::SendIpcpAck => {
                eprintln!("⚠️ Не реализовано: {:?}", state);
                state = PppState::Error("Не реализовано".into());
            }
            
            PppState::SendLcpRequest => {
                let packet = build_sstp_ppp_lcp_request();
                stream.write_all(&packet).await?;
                println!("📨 Отправлен LCP Configure-Request");
                state = PppState::WaitLcpRequest;
            }

            PppState::WaitLcpRequest => {
                let ppp = ppp.unwrap(); // безопасно, мы уже проверили выше
                if ppp.protocol == 0xC021 && ppp.code == 0x01 {
                    let ack = build_sstp_packet_from_ppp(0x02, &ppp);
                    stream.write_all(&ack).await?;
                    state = PppState::SendPapAuth;
                } else {
                    state = PppState::Error("Неожиданный LCP".into());
                }
            }

            PppState::SendPapAuth => {
                let auth = wrap_ppp_pap_packet(id_counter, user, pwd);
                stream.write_all(&auth).await?;
                id_counter += 1;
                state = PppState::WaitPapAck;
            }

            PppState::WaitPapAck => {
                let ppp = ppp.unwrap();
                if ppp.protocol == 0xC023 && ppp.code == 0x02 {
                    println!("✅ PAP Authenticate-Ack");
                    
                    // 💬 Вставляем CALL_CONNECTED
                    let packet = build_sstp_call_connected_packet();
                    stream.write_all(&packet).await?;
                    println!("📡 Отправлен SSTP CALL_CONNECTED");
                    
                    state = PppState::SendIpcpRequest;
                } else {
                    state = PppState::Error("Ожидался PAP Ack".into());
                }
            }

            PppState::SendIpcpRequest => {
                let ipcp = build_ipcp_configure_request_packet(id_counter);
                stream.write_all(&ipcp).await?;
                id_counter += 1;
                state = PppState::WaitIpcpRequest;
            }

            PppState::WaitIpcpRequest => {
                let ppp = ppp.unwrap();
                if ppp.protocol == 0x8021 && ppp.code == 0x01 {
                    println!("📥 IPCP Configure-Request: ID={}, len={}", ppp.id, ppp.length);
            
                    // Пытаемся достать IP из Option 3
                if let Some(ip) = extract_option_value(&ppp.payload, 0x03) {
                    println!("📦 Сервер предлагает IP: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                    println!("✅ Принимаем IP, отправляем Configure-Ack");
                    let ack = build_ipcp_configure_ack(ppp.id, ip);
                    stream.write_all(&ack).await?;
                    state = PppState::WaitIpcpNakWithOffer;
                } else {
                    println!("⚠️ Нет опции IP-адреса в Configure-Request — игнорируем");
                    state = PppState::Error("IPCP Configure-Request без IP-опции".into());
                }
                    
                } else {
                    state = PppState::Error("❌ Неожиданный IPCP пакет".into());
                }
            }

            PppState::WaitIpcpNakWithOffer => {
                let ppp = ppp.unwrap();
            
                if ppp.protocol == 0x8021 && ppp.code == 0x03 {
                    println!("📥 Получен IPCP Configure-Nak (ID = {})", ppp.id);
            
                    for (k, v) in extract_all_ipcp_options(&ppp.payload) {
                        println!("🔧 option {} → {}.{}.{}.{}", k, v[0], v[1], v[2], v[3]);
                    }

                    let ip = extract_option_value(&ppp.payload, 0x03).unwrap_or([0, 0, 0, 0]);
                    let dns = extract_option_value(&ppp.payload, 0x81).unwrap_or([0, 0, 0, 0]);
            
                    println!("📦 IP  = {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                    println!("📦 DNS = {}.{}.{}.{}", dns[0], dns[1], dns[2], dns[3]);
            
                    // отправляем новый Configure-Request с этими параметрами
                    let req = build_ipcp_request_with_only_ip(ip, id_counter);
                    println!("id {} nak request only ip again ({} байт): {:02X?}", id_counter, req.len(), &req[..req.len()]);
                    stream.write_all(&req).await?;
                    id_counter += 1;                
                    state = PppState::WaitIpcpFinalAck;
                } else {
                    state = PppState::Error("❌ Ожидался IPCP Nak с предложением IP".into());
                }
            }

            PppState::SendIpcpCustomRequest => {
                let ppp = ppp.unwrap();
                println!("📤 Шлём свой IPCP Configure-Request (0.0.0.0 + DNS)");            
                let req = build_ipcp_request_any_ip(ppp.id);
                stream.write_all(&req).await?;
                state = PppState::WaitIpcpResponse;
            }

            PppState::WaitIpcpFinalAck => {
                let ppp = ppp.unwrap();
            
                if ppp.protocol == 0x8021 && ppp.code == 0x02 {
                    println!("🎉 IPCP Configure-Ack, IP согласован!");
                    state = PppState::Done;
                } else {
                    state = PppState::Error("❌ Ожидался IPCP Ack".into());
                }
            }

            PppState::Done => {
                println!("🎉 Соединение установлено!");
                break;
            }

            PppState::Error(e) => {
                eprintln!("❌ Ошибка: {}", e);
                break;
            }
        }

        println!("____________");
    }




    Ok(())
}