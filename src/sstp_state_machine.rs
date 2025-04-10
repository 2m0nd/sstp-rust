use tokio::select;
use tokio_util::sync::CancellationToken;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::str::FromStr;
use tokio::time::{Duration, timeout};
use std::io::Write;
use std::net::Ipv4Addr;
use anyhow::Result;
use crate::log::*;
use crate::sstp::*;
use crate::parser::*;
use crate::dhcp::*;
use uuid::Uuid;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use tokio::{net::TcpStream, io::{AsyncReadExt, AsyncWriteExt}};
use std::time::Instant;
use tokio::io::{ split, ReadHalf, WriteHalf};
use tokio_rustls::client::TlsStream;
use crate::types::PppSessionInfo;
use crate::types::PppState;
#[cfg(target_os = "linux")]
use crate::async_tun_nix::AsyncTun;

#[cfg(not(target_os = "linux"))]
use crate::async_tun::AsyncTun;

pub async fn run_sstm_state_machine(
    server_ip: &str,
    usr: &str,
    pwd: &str,
    stream: &mut TlsStream<TcpStream>,
) -> Result<Option<PppSessionInfo>, Box<dyn std::error::Error>> {


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
    println!("� HTTP ответ от сервера:\n{}", response);

    if !response.contains("200 OK") {
        return Err("❌ Не удалось пройти SSTP INIT: сервер не ответил 200 OK".into());
    }

    let hello = build_sstp_hello(correlation_id);
    println!("📏 Hello длина: {} байт", hello.len());
    stream.write_all(&hello).await?;
    println!("📨 Отправлен SSTP Hello");

    let n = stream.read(&mut buf).await?;
    println!("📥 Ответ на Hello ({} байт): {:02X?}", n, &buf[..n]);

    let buf = [0u8; 1500];
    let mut state = PppState::SendLcpRequest;
    let mut id_counter: u8 = 0;

    let mut session_info: Option<PppSessionInfo> = None;
    let mut leftover_buf = Vec::new();
    let mut pending_packets = VecDeque::new();
    let mut sent_lcp_requests: HashMap<u8, Vec<u8>> = HashMap::new();

    loop {
        if matches!(state,
            PppState::WaitLcpRequest |
            PppState::WaitLcpReject |
            PppState::WaitPapAck |
            PppState::WaitLcpNak |
            PppState::WaitLcpAck |
            PppState::WaitIpcpFinalAck |
            PppState::WaitIpcpRequest |
            PppState::WaitIpcpReject |
            PppState::WaitIpcpNakWithOffer |
            PppState::WaitEchoRequest |
            PppState::WaitDhcpAck
        ) {
            read_and_parse_all(stream, &mut leftover_buf, &mut pending_packets).await?;
        }

        match state {
            PppState::SendLcpRequest => {
                let (packet, options_payload) = build_sstp_ppp_lcp_request_with_options(id_counter);
                stream.write_all(&packet).await?;
                log_line(&format!("Send LCP Configure-Request #{}", id_counter));
                
                // 💾 сохраняем только payload (опции) по ID
                sent_lcp_requests.insert(id_counter, options_payload.clone());
            
                for (typ, data) in extract_all_lcp_options(&options_payload) {
                    log_send_lcp(id_counter, typ, &data);
                }
            
                id_counter += 1;
                state = PppState::WaitLcpRequest;
            }

            PppState::WaitLcpRequest => {
                if let Some(ppp) = take_matching_packet(&mut pending_packets, |p| p.protocol == 0xC021 && p.code == 0x01) {
                    log_line(&format!("Received LCP Configure-Request *{}", ppp.id));
            
                    // лог опций
                    for (opt_type, opt_data) in extract_all_lcp_options(&ppp.payload) {
                        log_recv_lcp(ppp.id, opt_type, &opt_data);
                    }
            
                    if let Some(auth_proto) = extract_option_value_u16(&ppp.payload, 0x03) {
                        let ack_payload = [0x03, 0x04, auth_proto[0], auth_proto[1]];
                        let ack = wrap_lcp_packet(0x02, ppp.id, &ack_payload);
            
                        stream.write_all(&ack).await?;
            
                        log_line(&format!("Send LCP Configure-Ack *{}", ppp.id));
                        log_send_lcp(ppp.id, 0x03, &auth_proto);
            
                        log_line("Use PAP to authenticate");
                        state = PppState::WaitLcpReject;
                    } else {
                        state = PppState::Error("Неожиданный LCP без auth_proto".into());
                    }
                } else {
                    continue;
                }
            }

            PppState::WaitLcpReject => {
                if let Some(ppp) = take_matching_packet(
                    &mut pending_packets, |p| p.protocol == 0xC021 && p.code == 0x04) {
                    let rejected_opts = extract_all_lcp_option_types(&ppp.payload);
                    let old_payload = sent_lcp_requests.get(&ppp.id).cloned();

                    // 🧾 Логируем заголовок Reject
                    log_line(&format!("Received LCP Configure-Reject #{}", ppp.id));

                    // 🧾 Логируем каждую отклонённую опцию
                    for (typ, data) in extract_all_lcp_options(&ppp.payload) {
                        log_recv_lcp(ppp.id, typ, &data);
                    }

                    if let Some(payload) = old_payload {


                        let filtered_payload = remove_rejected_lcp_options(&payload, &rejected_opts);
                        let new_req = wrap_lcp_packet(0x01, id_counter, &filtered_payload);
                        stream.write_all(&new_req).await?;

                        log_line(&format!("Send LCP Configure-Request #{}", id_counter));
                        for (typ, data) in extract_all_lcp_options(&filtered_payload) {
                            log_send_lcp(id_counter, typ, &data);
                        }

                        id_counter += 1;
                        state = PppState::WaitLcpNak;
                    } else {
                        state = PppState::Error("Не найден исходный LCP по ID".into());
                    }
                } else {
                    continue;
                }
            }

            PppState::WaitLcpNak => {
                if let Some(ppp) = take_matching_packet(
                    &mut pending_packets, |p| p.protocol == 0xC021 && p.code == 0x03
                ) {
                    log_line(&format!("Received LCP Configure-Nak #{}", ppp.id));
            
                    if let Some(mru) = extract_option_value_u16(&ppp.payload, 0x01) {
                        log_recv_lcp(ppp.id, 0x01, &mru);
            
                        let (new_req, options_payload) = build_lcp_configure_request_filtered_with_mru(id_counter, mru);
                        log_line(&format!("Send LCP Configure-Request #{}", id_counter));
                        log_send_lcp(id_counter, 0x01, &mru);
            
                        stream.write_all(&new_req).await?;
                        log_send("LCP Configure-Request (after NAK)", &new_req, &state);
                        sent_lcp_requests.insert(id_counter, options_payload.clone());

                        id_counter += 1;
                        state = PppState::WaitLcpAck;
                    } else {
                        state = PppState::Error("LCP NAK без MRU".into());
                    }
                } else {
                    continue;
                }
            }

            PppState::WaitLcpAck => {
                if let Some(ppp) = take_matching_packet(
                    &mut pending_packets, |p| p.protocol == 0xC021 && p.code == 0x02) {
                    log_line(&format!("Received LCP Configure-Ack #{}", ppp.id));
            
                    if let Some(sent_payload) = sent_lcp_requests.get(&ppp.id) {
                        for (typ, val) in extract_all_lcp_options(sent_payload) {
                            log_recv_lcp(ppp.id, typ, &val);
                        }
                    } else {
                        log_line("⚠️ Не найден отправленный LCP Request для логирования опций");
                    }
            
                    log_line("LCP configuration done");
                    state = PppState::SendPapAuth;
                } else {
                    continue;
                }
            }

            PppState::SendPapAuth => {
                log_line("Verifying login credentials");
                id_counter = 0;
                log_line(&format!("Send PAP Request #{}", id_counter));
                let auth = wrap_ppp_pap_packet(id_counter, &usr, &pwd);
                stream.write_all(&auth).await?;
                log_send("PAP Auth", &auth, &state);
            
                id_counter += 1;
                state = PppState::WaitPapAck;
            }

            PppState::WaitPapAck => {
                if let Some(ppp) = take_matching_packet(&mut pending_packets, |p| p.protocol == 0xC023 && p.code == 0x02) {
                    log_line(&format!("Received PAP Ack #{}", ppp.id));
                    log_line("PAP authentication succeeded");
            
                    let packet = build_sstp_call_connected_packet();
                    stream.write_all(&packet).await?;
                    log_line("Send CALL_CONNECTED");
                    log_send("CALL_CONNECTED", &packet, &state);
            
                    state = PppState::SendIpcpRequest;
                } else {
                    continue;
                }
            }

            PppState::SendIpcpRequest => {
                log_line("Start IPCP negotiation");
                id_counter = 3;
            
                let ipcp = build_ipcp_configure_request_packet(id_counter);
                log_line(&format!("Send IPCP Configure-Request #{}", id_counter));
                log_line("Memory usage: 6.9MB"); // приближение к реальному выводу
            
                // println!("🔍 IPCP packet size: {}", ipcp.len());
                // println!("🔍 First 16 bytes: {:02X?}", &ipcp[..16.min(ipcp.len())]);

                // Срезаем SSTP + PPP
                let ipcp_payload = if ipcp.len() >= 8 {
                    &ipcp[8..]
                } else {
                    state = PppState::Error("IPCP packet слишком короткий для анализа".into());
                    continue;
                };
            
                let options = &ipcp_payload[4..]; // пропускаем Code, ID, Length
                for (option_type, data) in extract_all_ipcp_options(options) {
                    log_send_ipcp(id_counter, option_type, &data); // или log_send_ipcp()
                }
            
                stream.write_all(&ipcp).await?;
                log_send("IPCP Request", &ipcp, &state);
            
                sent_lcp_requests.insert(id_counter, options.to_vec());

                id_counter += 1;
                state = PppState::WaitIpcpRequest;
            }

            PppState::WaitIpcpRequest => {
                if let Some(ppp) = take_matching_packet(&mut pending_packets, |p| p.protocol == 0x8021 && p.code == 0x01) {
                    log_line(&format!("Received IPCP Configure-Request *{}", ppp.id));
            
                    // Пропускаем заголовок IPCP (4 байта: Code, ID, Length)
                    for (opt_type, data) in extract_all_ipcp_options(&ppp.payload) {
                        log_recv_ipcp(ppp.id, opt_type, &data);
                    }

                    if let Some(ip) = extract_option_value_u32(&ppp.payload, 0x03) {
                        let ack = build_ipcp_configure_ack(ppp.id, ip);
                        log_line(&format!("Send IPCP Configure-Ack *{}", ppp.id));
                        log_send_ipcp(ppp.id, 0x03, &ip);
                        log_line(&format!("Peer IP {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));            
                        stream.write_all(&ack).await?;
                        log_send("IPCP Ack", &ack, &state);
                        state = PppState::WaitIpcpReject;
                    } else {
                        state = PppState::Error("IPCP Configure-Request без IP-опции".into());
                    }
                } else {
                    continue;
                }
            }

            PppState::WaitIpcpReject => {
                if let Some(ppp) = take_matching_packet(
                    &mut pending_packets, 
                    |p| p.protocol == 0x8021 && p.code == 0x04
                ) {
                    log_line(&format!("Received IPCP Configure-Reject #{}", ppp.id));
            
                    // ✅ Лог опций из Reject-пакета
                    for (typ, data) in extract_all_ipcp_options(&ppp.payload) {
                        log_recv_ipcp(ppp.id, typ, &data);
                    }
            
                    // ✅ Получаем старый payload, который мы отправляли
                    let old_payload = sent_lcp_requests.get(&ppp.id).cloned();
                    if let Some(payload) = old_payload {
                        // ✅ Определяем, какие опции были отвергнуты
                        let rejected_types = extract_all_ipcp_option_types(&ppp.payload);
                        // ✅ Удаляем отвергнутые опции
                        let filtered_payload = remove_rejected_ipcp_options(&payload, &rejected_types);
                        // ✅ Строим новый пакет
                        let new_req = wrap_ipcp_packet(0x01, id_counter, &filtered_payload);
            
                        // ✅ Лог заголовка нового запроса
                        log_line(&format!("Send IPCP Configure-Request #{}", id_counter));
                        for (typ, data) in extract_all_ipcp_options(&filtered_payload) {
                            log_send_lcp(id_counter, typ, &data);
                        }
            
                        // ✅ Отправка пакета
                        stream.write_all(&new_req).await?;
                        log_send("IPCP Configure-Request (after Reject)", &new_req, &state);
            
                        // ✅ Сохраняем для последующей обработки (в NAK и ACK)
                        sent_lcp_requests.insert(id_counter, filtered_payload);
            
                        // ✅ Обновляем счётчик и переходим в следующий стейт
                        id_counter += 1;
                        state = PppState::WaitIpcpNakWithOffer;
                    } else {
                        state = PppState::Error("❌ Не найден предыдущий IPCP пакет по ID".into());
                    }
                } else {
                    continue;
                }
            }
            

            PppState::WaitIpcpNakWithOffer => {
                if let Some(ppp) = take_matching_packet(&mut pending_packets, |p| p.protocol == 0x8021 && p.code == 0x03) {
                    log_line(&format!("Received IPCP Configure-Nak #{}", ppp.id));
            
                    let nak_options = extract_all_ipcp_options(&ppp.payload);
                    for (typ, data) in &nak_options {
                        log_recv_lcp(ppp.id, *typ, data);
                    }
            
                    let ip = to_array_4(nak_options.get(&3).cloned().unwrap_or(vec![0, 0, 0, 0]));
                    let dns = to_array_4(nak_options.get(&129).cloned().unwrap_or(vec![0, 0, 0, 0]));
            
                    log_line(&format!("Send IPCP Configure-Request #{}", id_counter));
                    log_send_ipcp(id_counter, 3, &ip);
                    log_send_ipcp(id_counter, 129, &dns);
            
                    let final_ipcp = build_ipcp_request_with_ip_and_dns(id_counter, ip, dns);
                    stream.write_all(&final_ipcp).await?;
                    log_send("IPCP Request (final)", &final_ipcp, &state);
            
                    id_counter += 1;
                    state = PppState::WaitIpcpFinalAck;
                } else {
                    continue;
                }
            }

            PppState::WaitIpcpFinalAck => {
                if let Some(ppp) = take_matching_packet(&mut pending_packets, |p| p.protocol == 0x8021 && p.code == 0x02) {
                    log_line(&format!("Received IPCP Configure-Ack #{}", ppp.id));
            
                    let opts = extract_all_ipcp_options(&ppp.payload);
            
                    for (typ, data) in &opts {
                        log_recv_lcp(ppp.id, *typ, data);
                    }
            
                    let ip = match opts.get(&0x03) {
                        Some(vec) if vec.len() == 4 => [vec[0], vec[1], vec[2], vec[3]],
                        _ => [0, 0, 0, 0],
                    };
                    let dns1 = match opts.get(&0x81) {
                        Some(vec) if vec.len() == 4 => Some([vec[0], vec[1], vec[2], vec[3]]),
                        _ => None,
                    };
                    let dns2 = match opts.get(&0x83) {
                        Some(vec) if vec.len() == 4 => Some([vec[0], vec[1], vec[2], vec[3]]),
                        _ => None,
                    };
            
                    log_line(&format!("Local IP {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                    if let Some(dns1) = dns1 {
                        log_line(&format!("Primary DNS {}.{}.{}.{}", dns1[0], dns1[1], dns1[2], dns1[3]));
                    }
                    if let Some(dns2) = dns2 {
                        log_line(&format!("Secondary DNS {}.{}.{}.{}", dns2[0], dns2[1], dns2[2], dns2[3]));
                    }
            
                    log_line("IPCP configuration done");
            
                    session_info = Some(PppSessionInfo { ip, dns1, dns2 });
                    
                    state = PppState::DhcpSendInfo;
            
                } else {
                    continue;
                }
            }

            PppState::DhcpSendInfo => {
                log_line("Send DHCP Inform");
            
                if let Some(info) = &session_info {
                    // Собираем DHCP Inform → в PPP-IP-UDP-DHCP
                    let dhcp_packet = build_dhcp_inform_ppp_packet(info.ip);
            
                    // Отправляем его
                    stream.write_all(&dhcp_packet).await?;
                    log_send("DHCP Inform", &dhcp_packet, &state);
            

                    // Переход в следующее состояние
                    state = PppState::WaitEchoRequest;
                } else {
                    state = PppState::Error("❌ Нет IP-адреса для DHCP".into());
                }
            }            

            PppState::WaitEchoRequest =>  {
                if let Some(ppp) = take_matching_packet(
                    &mut pending_packets, |p| {
                    p.protocol == 0xC021 && p.code == 0x09
                }) {
                    log_line(&format!("Received LCP Echo Request"));            
                    let reply = wrap_lcp_packet(0x0A, ppp.id, &ppp.payload); // Echo Reply
                    stream.write_all(&reply).await?;
            
                    log_line("Send LCP Echo Reply");
                    log_send("LCP Echo Reply", &reply, &state);
            
                    // Возвращаемся в ожидание DHCP ACK или следующую задачу
                    state = PppState::WaitDhcpAck;
                } else {
                    continue;
                }
            }

            PppState::WaitDhcpAck => {
                if let Some(ppp) = take_matching_packet(&mut pending_packets, |p| p.protocol == 0x0021) {
                    let payload = &ppp.payload;
            
                    if let Some(dhcp_opts) = parse_dhcp_ack_from_ip_payload(payload) {
                        log_line("Received DHCP Ack");
            
                        for (opt, data) in &dhcp_opts {
                            log_line(&format!("DHCP: Option {:02}={:X?}", opt, data));
                        }
            
                        // Распаковка конкретных значений
                        if let Some(server_ip) = dhcp_opts.get(&54) {
                            log_line(&format!("DHCP: Server IP {}.{}.{}.{}", server_ip[0], server_ip[1], server_ip[2], server_ip[3]));
                        }
            
                        if let Some(mask) = dhcp_opts.get(&1) {
                            log_line(&format!("DHCP: Subnet mask {}.{}.{}.{}", mask[0], mask[1], mask[2], mask[3]));
                            log_line(&format!("Subnet mask {}.{}.{}.{}", mask[0], mask[1], mask[2], mask[3]));
                        }
            
                        if let Some(dns) = dhcp_opts.get(&6) {
                            log_line(&format!("DHCP: DNS {}.{}.{}.{}", dns[0], dns[1], dns[2], dns[3]));
                        }
                        
                        state = PppState::Done;
                    } else {
                        state = PppState::Error("❌ DHCP Ack parse error".into());
                    }
                } else {
                    continue;
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

            _ => {
                state = PppState::Error("Необработанное состояние".into());
            }
        }
    }

    Ok(session_info)
}

/// Финальный шаг после PPP FSM: создаём TUN и запускаем туннелирование
pub async fn setup_and_start_tunnel(
    stream: TlsStream<TcpStream>, 
    server_ip: &str, ip: Ipv4Addr,
    cancellation_token: CancellationToken,) -> Result<AsyncTun, std::io::Error> {

    let vpn_server_ip = Ipv4Addr::from_str(&server_ip)
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    let dev = AsyncTun::new(
        vpn_server_ip,
        ip,
        ip,
        Ipv4Addr::new(255, 255, 255, 0),
    ).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    println!("запустили TUN:{}", dev.name());

    // ✅ Разделяем SSTP поток
    let (reader, writer) = split(stream);

    // ✅ Запускаем туннелирование
    let dev_clone = dev.clone();
    start_tun_forwarding(dev, reader, writer, cancellation_token).await;

    Ok(dev_clone)
}

/// Стартует IP-туннель: обменивается трафиком между SSTP и TUN
pub async fn start_tun_forwarding(
    tun: AsyncTun,
    mut reader: ReadHalf<TlsStream<TcpStream>>,
    writer: WriteHalf<TlsStream<TcpStream>>,
    cancellation_token: CancellationToken,
) -> std::io::Result<()> {
    println!("🟢 TUN активен. Запускаем туннелирование...");
    let writer = Arc::new(TokioMutex::new(writer));

    let timeout_duration = Duration::from_millis(200);
    let (tun_sender, mut tun_receiver) = 
        tokio::sync::mpsc::channel::<Vec<u8>>(1000 * 30);
    let (sstp_sender, mut sstp_receiver) = 
        tokio::sync::mpsc::channel::<Vec<u8>>(1000 * 30);
    let tun_reader = tun.clone();
    let tun_writer = tun.clone();

    let delay = Duration::from_micros(10);
    //📤 uplink: TUN → SSTP
    {
        let tun_sender = tun_sender.clone();
        tokio::spawn({
            let cancellation_token = cancellation_token.clone();
            async move {
                loop {
                    // Проверка отмены
                    if cancellation_token.is_cancelled() {
                        tun_sender.closed().await;
                        println!("❌ Поток чтения из TUN отменен.");
                        break;
                    }

                    //let mut tun_timer = Instant::now();
                    // Таймаут при чтении из TUN
                    let result = timeout(timeout_duration, tun_reader.read()).await;
                    
                    match result {
                        Ok(Ok(buf)) => {
                            let ip_data = &buf[4..buf.len()]; // пропускаем 4 байта заголовка macOS TUN
                            let packet = wrap_ip_in_ppp_sstp(&ip_data);
                            //println!("📥 tun read packet size {} time: {} µs", packet.len(), tun_timer.elapsed().as_millis());
                            match tun_sender.send(packet).await {
                                Ok(_) => (),
                                Err(e) => eprintln!("❌ Ошибка отправки в канал: {e}"),
                            }
                        }
                        Ok(Err(e)) => {
                            eprintln!("❌ Ошибка чтения из TUN: {e}");
                        }
                        Err(_) => {
                            eprintln!("❌ Тайм-аут при чтении из TUN.");
                        }
                    }
                    tokio::task::yield_now().await;
                }
            }
        });
    }
    {

        // Поток для чтения данных из канала
        tokio::spawn({
            let cancellation_token = cancellation_token.clone(); 
            async move {
                let mut writer = writer.lock().await;
                loop {
                    select! {
                        _ = cancellation_token.cancelled() => {
                            println!("❌ Поток записи в SSTP отставнолен (2).");
                            break;
                        }
                        Some(packet) = tun_receiver.recv() => {
                            //println!("поток 2 работает...");
                            if let Err(e) = writer.write_all(&packet).await {
                                eprintln!("❌ Ошибка записи в SSTP: {e}");
                            }
                            tokio::task::yield_now().await;
                        }
                        else => {
                            // Если канал закрыт, завершить работу
                            println!("Канал закрыт.");
                            break;
                        }
                    }                    
                }
            }
        });
    }

    // 📥 downlink: SSTP → TUN
    {
        let tun_sender = tun_sender.clone();
        tokio::spawn({
            let cancellation_token = cancellation_token.clone(); 
            async move {
            
                let mut buf = [0u8; 1600];
                loop {
                    // Проверка отмены
                    if cancellation_token.is_cancelled() {
                        sstp_sender.closed().await;
                        println!("❌ Поток чтения SSTP оставнолен (3).");
                        break;
                    }//else{println!("поток 3 работает...")}
                    //println!("Читаем sstp stream");
    
                    let result = timeout(timeout_duration, reader.read(&mut buf)).await;
                    match result {
                        Ok(Ok(0)) => {
                            eprintln!("🔌 SSTP соединение закрыто");
                            break;
                        }
                        Ok(Ok(n)) => {
                            // Здесь идет обработка данных
                            if buf[..n].starts_with(&[0x10, 0x01]) && buf[4..6] == [0x00, 0x05] {
                                println!("📶 Получен SSTP ECHO_REQUEST");
                                let echo_resp = build_sstp_echo_response().to_vec();
                                match tun_sender.send(echo_resp).await {
                                    Ok(_) => (),
                                    Err(e) => eprintln!("❌ Ошибка отправки: {e}"),
                                }
                                println!("✅ Записан в очередь SSTP ECHO_RESPONSE");
                            }
    
                            if let Some(ip_data) = parse_ppp_ip_packet(&buf[..n]) {
                                let ip_data = ip_data.to_vec(); // выделяем для send в blocking
                                let mut buf = Vec::with_capacity(4 + ip_data.len()); //apple header ip
                                buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // AF_INET
                                buf.extend_from_slice(&ip_data); // сам IP-пакет
    
                                match sstp_sender.send(buf).await {
                                    Ok(_) => (),
                                    Err(e) => eprintln!("❌ Ошибка записи в TUN очередь: {e}"),
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            eprintln!("❌ Ошибка чтения из SSTP: {e}");
                        }
                        Err(_) => {
                            eprintln!("❌ Тайм-аут при чтении из SSTP.");
                        }
                    }
                    tokio::task::yield_now().await;
                }
            }
        });

        // ✉️ Поток записи в TUN из sstp_sender
        {
            tokio::spawn({
                let cancellation_token = cancellation_token.clone(); 
                async move {
                    let mut total_bytes = 0;
                    let period = 1;
                    let mut start = Instant::now();
                    loop{
                        select! {
                            _ = cancellation_token.cancelled() => {
                                println!("❌ Поток записи в TUN оставнолен (4).");
                                break;
                            }
                            Some(packet) = sstp_receiver.recv() => {
                                total_bytes += packet.len();

                                //let mut tun_timer = Instant::now();
                                if let Err(e) = tun_writer.write(&packet).await {
                                    eprintln!("❌ Ошибка записи в TUN: {e}");
                                }
                                if start.elapsed() >= Duration::from_secs(period) {
                                    let seconds = start.elapsed().as_secs_f64(); // точнее, чем period * 1.0
                                    let speed = ((total_bytes as f64 / seconds) as f64 / 1024 as f64) as u32;
                                    println!("📈 [Запись TUN] Скорость: {} кб/сек", speed);
                                    total_bytes = 0;
                                    start = Instant::now();
                                }
                                //println!("📥 tun write packet size {} time: {} µs", packet.len(), tun_timer.elapsed().as_millis());
                                tokio::task::yield_now().await;
                            }
                            else => {
                                // Если канал закрыт, завершить работу
                                println!("Канал закрыт.");
                                break;
                            }
                        }   
                    }
                }
            });
        }
    }
    
    println!("!!!Threads reading and writing started.");

    Ok(())
}