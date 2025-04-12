use tokio::select;
use tokio_util::sync::CancellationToken;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::str::FromStr;
use tokio::time::{Duration, timeout};
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

    let timeout_duration = Duration::from_millis(1);
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
                            let ip_data = {
                                #[cfg(target_os = "macos")]
                                {
                                    &buf[4..] // пропускаем 4 байта заголовка macOS TUN
                                }
                            
                                #[cfg(not(target_os = "macos"))]
                                {
                                    &buf[..]
                                }
                            };
                            let packet = wrap_ip_in_ppp_sstp(&ip_data);
                            //println!("📥 tun read packet size {} time: {} µs", packet.len(), tun_timer.elapsed().as_millis());
                            match tun_sender.send(packet).await {
                                Ok(_) => (),
                                Err(e) => eprintln!("❌ Ошибка отправки в канал: {e}"),
                            }
                        }
                        Ok(Err(e)) => {
                            if e.kind() != std::io::ErrorKind::WouldBlock {
                                eprintln!("❌ Ошибка чтения из TUN: {e}");
                            }
                            // иначе — просто молча пропускаем
                        }
                        Err(_) => {
                            //eprintln!("❌ Тайм-аут при чтении из TUN.");
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
                                let mut buf = {
                                    #[cfg(target_os = "macos")]
                                    {
                                        let mut b = Vec::with_capacity(4 + ip_data.len());
                                        b.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // AF_INET
                                        b.extend_from_slice(&ip_data);
                                        b
                                    }
                                
                                    #[cfg(not(target_os = "macos"))]
                                    {
                                        ip_data.to_vec()
                                    }
                                };
    
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
                            //eprintln!("❌ Тайм-аут при чтении из SSTP.");
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