use dotenvy::dotenv;
use std::io::{self, Write};
use std::env;
use crate::ssl_verifiers::*;
use std::sync::Arc;
use tokio_rustls::rustls::client::ServerCertVerifier;

pub fn get_credentials() -> Result<(String, String, String, String), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        // Case 1: useEnv
        [_, mode] if mode == "useEnv" => {
            dotenv()?; // ← читаем .env
            let server = env::var("SSTP_SERVER")?;
            let user = env::var("SSTP_USER")?;
            let password = env::var("SSTP_PASSWORD")?;
            let ssl_cert_fingerprint = env::var("SERVER_CERT_FINGERPRINT")?;
            Ok((server, user, password, ssl_cert_fingerprint))
        }

        // Case 2: useInline server user password
        [_, mode, server, user, password, ssl_cert_fingerprint]
             if mode == "useInline" => {
            Ok((server.clone(), user.clone(), password.clone(), ssl_cert_fingerprint.clone()))
        }

        // Anything else
        _ => Err("Please either use 'useEnv' with environment variables or 'useInline <server> <user> <password>'".into()),
    }
}

pub fn parse_sha256_hex(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let clean = s.replace(":", "").replace(" ", "").to_lowercase();

    let bytes = hex::decode(clean)?;
    if bytes.len() != 32 {
        return Err("Invalid SHA256 length (expected 32 bytes)".into());
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn make_verifier(ssl_cert_fingerprint: &str) -> Arc<dyn ServerCertVerifier> {
    if ssl_cert_fingerprint.eq_ignore_ascii_case("no-check") {
        print!("⚠️  Вы действительно хотите отключить проверку TLS-сертификата? (y/N): ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        if input.trim().to_lowercase() != "y" {
            panic!("❌ Отменено пользователем.");
        }

        println!("⚠️  Проверка отключена. Используется `DisabledVerifier`.");
        Arc::new(DisabledVerifier)
    } else {
        let parsed = parse_sha256_hex(ssl_cert_fingerprint)
            .expect("❌ Невалидный SHA256 отпечаток сертификата");
        Arc::new(PinnedCertVerifier::new(parsed))
    }
}