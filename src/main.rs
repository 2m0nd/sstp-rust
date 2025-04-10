use dotenvy::dotenv;
use sstp_rust::sstp_state_machine::*;
use sstp_rust::route::*;
use sstp_rust::DEBUG_PARSE;
use sstp_rust::types::*;
use sstp_rust::ssl_verifiers::DisabledVerifier;

use std::env;
use std::net::Ipv4Addr;
use anyhow::Result;
use std::sync::Arc;
use std::net::IpAddr;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{
    ClientConfig, ServerName,
};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    println!("Start vpn client...");

    let (server_ip, user, pwd) = get_credentials().expect("Not allowed parameters");
    
    let ssl_addr = format!("{server_ip}:443");

    println!("Try connect to: {} by login: {}", server_ip, user);

    let domain = ServerName::IpAddress(server_ip.parse::<IpAddr>()?);

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(DisabledVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(&ssl_addr).await?;
    let mut stream = connector.connect(domain, tcp).await?;

    println!("✅ TLS подключение установлено");
  
    // --- Основной FSM цикл ---
    let session_info: Option<PppSessionInfo> = run_sstm_state_machine(&server_ip, &user, &pwd, &mut stream).await?;

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
        let tun = setup_and_start_tunnel(stream, &server_ip, Ipv4Addr::from(info.ip), cancellation_token)
                .await.expect("Failed start tunel");

        println!("🟢TUN активен, туннелирование запущено. Ждём трафик...");  

        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl-c");    

        tun.restore_routes("192.168.1.1", &server_ip).expect("Failed reset default routes");

        std::process::exit(0);

    } else {
        eprintln!("❌ Стейт-машина не вернула сессию");
    }

    Ok(())
}


pub fn get_credentials() -> Result<(String, String, String), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        // Case 1: useEnv
        [_, mode] if mode == "useEnv" => {
            dotenv()?; // ← читаем .env
            let server = env::var("SSTP_SERVER")?;
            let user = env::var("SSTP_USER")?;
            let password = env::var("SSTP_PASSWORD")?;
            Ok((server, user, password))
        }

        // Case 2: useInline server user password
        [_, mode, server, user, password] if mode == "useInline" => {
            Ok((server.clone(), user.clone(), password.clone()))
        }

        // Anything else
        _ => Err("Please either use 'useEnv' with environment variables or 'useInline <server> <user> <password>'".into()),
    }
}