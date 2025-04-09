mod sstp;
mod log;
mod route;
mod async_tun;
mod sstp_state_machine;
mod types;
mod parser;
mod ssl_verifiers;

use sstp_state_machine::*;
use route::*;
use async_tun::AsyncTun;
use log::*;
use tokio::select;
use sstp_rust::DEBUG_PARSE;
use tokio::time::{Duration, timeout};
use std::io::Write;
use std::net::Ipv4Addr;
use anyhow::Result;
use crate::sstp::*;
use crate::parser::*;
use crate::types::*;
use ssl_verifiers::DisabledVerifier;
use uuid::Uuid;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use std::net::IpAddr;
use tokio::{net::TcpStream, io::{AsyncReadExt, AsyncWriteExt}};
use tokio_rustls::TlsConnector;
use std::time::Instant;
use tokio_rustls::rustls::{
    ClientConfig, ServerName,
};
use tokio::io::{ split, ReadHalf, WriteHalf};
use tokio_rustls::client::TlsStream;
mod dhcp;
use dhcp::*;
use std::sync::atomic::Ordering;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let user = "AHC\\test_user_client";
    let pwd = "EXAPLME_PWD";
    let server_ip = "SSTP_SERVER_IP_ADDRESS";
    let addr = format!("{server_ip}:443");

    let domain = ServerName::IpAddress(server_ip.parse::<IpAddr>()?);

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(DisabledVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(&addr).await?;
    let mut stream = connector.connect(domain, tcp).await?;

    println!("✅ TLS подключение установлено");
  
    // --- Основной FSM цикл ---
    let session_info: Option<PppSessionInfo> = run_sstm_state_machine(server_ip, user, pwd, &mut stream).await?;

    //смотрим че дальше летает с этого момента
    //DEBUG_PARSE.store(true, Ordering::Relaxed);

    if let Some(info) = &session_info {
        println!("🌐 IP = {:?}, DNS = {:?}", info.ip, info.dns1);
        
        // Создаем CancellationToken
        let cancellation_token = CancellationToken::new();
        // Слушаем сигнал Ctrl+C, чтобы отменить задачи
        let cancellation_token_clone = cancellation_token.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
            println!("❌ Получен сигнал отмены (Ctrl+C). Останавливаем туннелирование...");
            cancellation_token_clone.cancel(); // Отменяем все задачи
        });
        
        //tunel start
        setup_and_start_tunnel(stream, server_ip, Ipv4Addr::from(info.ip), cancellation_token).await;

        println!("🟢123 TUN активен, туннелирование запущено. Ждём трафик...");  

        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl-c");    

        let _ = restore_default_route();

        std::process::exit(0);

    } else {
        eprintln!("❌ Стейт-машина не вернула сессию");
    }

    Ok(())
}
