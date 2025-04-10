use tokio_rustls::rustls::{
    Certificate, Error as TLSError, ServerName,
    client::{ServerCertVerifier, ServerCertVerified},
};
use sha2::{Digest, Sha256};

/// Проверяет, что сертификат совпадает с ожидаемым по SHA-256
pub struct PinnedCertVerifier {
    expected_fingerprint: [u8; 32],
}

impl PinnedCertVerifier {
    pub fn new(expected: [u8; 32]) -> Self {
        Self {
            expected_fingerprint: expected,
        }
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, TLSError> {
        let actual_fingerprint = Sha256::digest(&end_entity.0);
        if actual_fingerprint.as_slice() == self.expected_fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TLSError::General("❌ Сертификат не совпадает с ожидаемым!".to_string()))
        }
    }
}

pub struct DisabledVerifier;

impl ServerCertVerifier for DisabledVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, TLSError> {
        Ok(ServerCertVerified::assertion())
    }
}