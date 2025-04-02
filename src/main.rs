use tokio::{net::TcpStream, io::{AsyncReadExt, AsyncWriteExt}};
use tokio_rustls::{
    rustls::{
        Certificate, ClientConfig, Error as TLSError, ServerName, SignatureScheme,
        ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid,
        DigitallySignedStruct,
    },
    TlsConnector,
};
use std::{sync::Arc, time::SystemTime};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // IP или доменное имя SSTP-сервера
    let server_host = "SSTP_SERVER_IP_ADDRESS";
    let addr = format!("{}:443", server_host);
    let domain = ServerName::try_from(server_host)?; // для SNI

    // TLS: отключаем проверку сертификатов (НЕ ДЕЛАТЬ В БОЕВОЙ СЕТИ!)
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let tcp_stream = TcpStream::connect(addr).await?;
    let mut tls_stream = connector.connect(domain, tcp_stream).await?;

    println!("🔐 TLS-соединение установлено.");

    // Заглушка SSTP Hello (формат пакета упрощён)
    let sstp_hello = vec![
        0x10, 0x01, // Control Packet (SSTP)
        0x00, 0x10, // Длина (16 байт)
        // Здесь должны быть поля AVP, но пока пропущены
    ];
    tls_stream.write_all(&sstp_hello).await?;
    println!("📨 Отправлен SSTP Hello (заглушка)");

    // Чтение ответа
    let mut buf = [0u8; 4096];
    let n = tls_stream.read(&mut buf).await?;
    println!("📥 Получено {} байт от сервера", n);
    println!("{:02X?}", &buf[..n]);

    Ok(())
}

// Заглушка для отключения проверки сертификатов
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &Certificate,
        _signature: &[u8],
        _scheme: SignatureScheme,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        Ok(HandshakeSignatureValid::assertion())
    }
}
