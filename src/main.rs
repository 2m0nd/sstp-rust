mod sstp;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::Ipv4Addr;
use anyhow::Result;
mod parser;
mod ssl_verifiers;
use crate::sstp::*;
use crate::parser::*;
use ssl_verifiers::DisabledVerifier;
use uuid::Uuid;
use tun::{create, Configuration, platform::Device};
use tokio::io::{AsyncRead, AsyncWrite};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::Mutex as TokioMutex;
use std::net::IpAddr;
use tokio::{net::TcpStream, io::{AsyncReadExt, AsyncWriteExt}};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{
    Certificate, ClientConfig, Error as TLSError, ServerName,
    client::ServerCertVerifier,
    client::ServerCertVerified,
};
use tokio::{io::{ split, ReadHalf, WriteHalf}};
use tun::{platform::Device as Tun};
use tokio_rustls::client::TlsStream;
mod dhcp;
use dhcp::*;

#[derive(Debug)]
pub struct PppSessionInfo {
    pub ip: [u8; 4],
    pub dns1: Option<[u8; 4]>,
    pub dns2: Option<[u8; 4]>,
}

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

    let mut session_info: Option<PppSessionInfo> = None;

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

            PppState::WaitIpcpFinalAck => {
                let ppp = ppp.unwrap();
            
                if ppp.protocol == 0x8021 && ppp.code == 0x02 {
                    println!(
                        "🎉 IPCP Configure-Ack получен (ID = {}), IP согласован!",
                        ppp.id
                    );
            
                    // Парсим все опции
                    let opts = extract_all_ipcp_options(&ppp.payload);
                    let ip = opts.get(&0x03).copied().unwrap_or([0, 0, 0, 0]);
                    let dns1 = opts.get(&0x81).copied();
                    let dns2 = opts.get(&0x83).copied();
            
                    println!(
                        "📦 Назначенный IP: {}.{}.{}.{}",
                        ip[0], ip[1], ip[2], ip[3]
                    );
            
                    if let Some(dns1) = dns1 {
                        println!(
                            "📦 Primary DNS: {}.{}.{}.{}",
                            dns1[0], dns1[1], dns1[2], dns1[3]
                        );
                    }
                    if let Some(dns2) = dns2 {
                        println!(
                            "📦 Secondary DNS: {}.{}.{}.{}",
                            dns2[0], dns2[1], dns2[2], dns2[3]
                        );
                    }
            
                    session_info = Some(PppSessionInfo { ip, dns1, dns2 });
            
                    println!("✅ Сессия установлена: {session_info:#?}");

                    // 💬 Вставляем CALL_CONNECTED
                    let packet = build_sstp_call_connected_packet();
                    stream.write_all(&packet).await?;
                    println!("📡 Отправлен SSTP CALL_CONNECTED");
                    
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

        println!("____________________________");
    }

    perform_dhcp_handshake(&mut stream, session_info).await?;

    //setup_and_start_tunnel(stream).await?;

    //println!("🟢 TUN активен, туннелирование запущено. Ждём трафик...");

    //tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
    
    Ok(())
}

/// Финальный шаг после PPP FSM: создаём TUN и запускаем туннелирование
pub async fn setup_and_start_tunnel(stream: TlsStream<TcpStream>) -> std::io::Result<()> {
    // ✅ Создаём TUN интерфейс
    let mut config = Configuration::default();
    config.address((192, 168, 30, 11)) // ← подставь реальный, если получен из IPCP
          .netmask((255, 255, 255, 0))
          .up();

    let dev = create(&config).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("tun create failed: {e}"))
    })?;

    // ✅ Оборачиваем в Arc<Mutex<>>
    let dev =  Arc::new(Mutex::new(dev));

    // ✅ Разделяем SSTP поток
    let (reader, writer) = split(stream);

    // ✅ Запускаем туннелирование
    start_tun_forwarding(dev, reader, writer).await
}

/// Стартует IP-туннель: обменивается трафиком между SSTP и TUN
pub async fn start_tun_forwarding(
    dev: Arc<Mutex<Device>>,
    mut reader: ReadHalf<TlsStream<TcpStream>>,
    mut writer: WriteHalf<TlsStream<TcpStream>>,
) -> std::io::Result<()> {
    println!("🟢 TUN активен. Запускаем туннелирование...");
    let writer = Arc::new(TokioMutex::new(writer));

    //📤 uplink: TUN → SSTP
    {
        let dev = dev.clone();
        let writer = writer.clone();

        tokio::spawn(async move {
            loop {
                let buf = match tokio::task::spawn_blocking({
                    let dev = dev.clone();
                    move || {
                        let mut buf = [0u8; 1600];
                        let n = {
                            let mut locked = dev.lock().unwrap();
                            locked.read(&mut buf)
                        }?;
                        Ok::<_, std::io::Error>(buf[..n].to_vec())
                    }
                }).await {
                    Ok(Ok(data)) => data, // ✅ теперь buf будет Vec<u8>
                    Ok(Err(e)) => {
                        eprintln!("❌ Ошибка чтения из TUN: {e}");
                        continue; // 🔁 не break, чтобы buf не стал `()`
                    }
                    Err(e) => {
                        eprintln!("❌ spawn_blocking panic: {e}");
                        continue;
                    }
                };

                let packet = wrap_ip_in_ppp_sstp(&buf);
                let mut writer = writer.lock().await;
                if let Err(e) = writer.write_all(&packet).await {
                    eprintln!("❌ Ошибка записи в SSTP: {e}");
                }
            }
        });
    }

    // 📥 downlink: SSTP → TUN
    {
        let dev = dev.clone();
        let writer = writer.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 1600];
            loop {

                println!("Читаем sstp stream");

                let n = match reader.read(&mut buf).await {
                    Ok(0) => {
                        eprintln!("🔌 SSTP соединение закрыто");
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("❌ Ошибка чтения из SSTP: {e}");
                        break;
                    }
                };

                if buf[..n].starts_with(&[0x10, 0x01]) && buf[4..6] == [0x00, 0x05]
                {
                    println!("📶 Получен SSTP ECHO_REQUEST");
                    let echo_resp = build_sstp_echo_response().to_vec();
                    let mut writer = writer.lock().await;
                    if let Err(e) = writer.write_all(&echo_resp).await {
                        eprintln!("❌ Ошибка записи в SSTP: {e}");
                    }
                    println!("✅ Отправлен ECHO_RESPONSE");
                    continue;
                }

                if let Some(ip_data) = parse_ppp_ip_packet(&buf[..n]) {
                    let ip_data = ip_data.to_vec(); // выделяем для send в blocking
                    let dev = dev.clone();
                    tokio::task::spawn_blocking(move || {
                        let mut dev = dev.lock().unwrap();
                        dev.write_all(&ip_data)
                    })
                    .await
                    .ok(); // можно логировать ошибку при необходимости
                }
            }
        });

        println!("Thread reading and writing started.")
    }

    Ok(())
}

pub async fn perform_dhcp_handshake(
    stream: &mut TlsStream<TcpStream>,
    client_ip: [u8; 4],
) -> std::io::Result<()> {
    println!("📡 Отправляем DHCP INFORM...");

    let dhcp_packet = build_dhcp_inform_packet(client_ip);
    let sstp_packet = wrap_ip_in_ppp_sstp(&dhcp_packet);

    stream.write_all(&sstp_packet).await?;

    let mut buf = [0u8; 1600];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "SSTP закрыт"));
        }
        
        println!("📦 RAW: {:02X?}", &buf[..n]);

        // Или вытащи вручную payload из PPP/IP
        if buf.len() >= 8 && buf[4] == 0xFF && buf[5] == 0x03 && buf[6] == 0x00 && buf[7] == 0x21 {
            let ip = &buf[8..];
            if ip[9] == 0x11 { // UDP
                let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
                let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
                let sport = u16::from_be_bytes([ip[20], ip[21]]);
                let dport = u16::from_be_bytes([ip[22], ip[23]]);

                println!("📡 UDP {}:{} → {}:{}", src, sport, dst, dport);

                if dport == 68 {
                    let dhcp = &ip[28..];
                    println!("📨 DHCP?: {:02X?}", dhcp);
                }
            }
        }

        if let Some(ip_packet) = parse_ppp_ip_packet(&buf[..n]) {
            if let Some(dhcp_info) = try_parse_dhcp_ack(ip_packet) {
                println!("✅ DHCP Ack получен:");
                println!("   🌐 DNS: {}", Ipv4Addr::from(dhcp_info.dns));
                println!("   🛣  Gateway: {}", Ipv4Addr::from(dhcp_info.gateway));
                println!("   🧱 Subnet: {}", Ipv4Addr::from(dhcp_info.subnet_mask));
                break;
            }
        }
    }

    Ok(())
}