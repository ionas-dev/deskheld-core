//! Server-side rustls verifier used for Deskheld peer-to-peer trust flow.

use std::sync::Arc;

use rustls::{
    crypto::{
        CryptoProvider, ring::default_provider, verify_tls12_signature, verify_tls13_signature,
    },
    server::danger,
};

/// Certificate verifier that accepts client certificates during handshake.
///
/// Peer trust is decided later using stored certificate fingerprints.
#[derive(Debug)]
pub struct CertVerifier(Arc<CryptoProvider>);

impl CertVerifier {
    /// Creates a new verifier backed by rustls's default crypto provider.
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(default_provider())))
    }
}

impl danger::ClientCertVerifier for CertVerifier {
    /// Accepts client certificates during TLS handshake.
    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<danger::ClientCertVerified, rustls::Error> {
        Ok(danger::ClientCertVerified::assertion())
    }

    /// Verifies TLS 1.2 handshake signatures using rustls defaults.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    /// Verifies TLS 1.3 handshake signatures using rustls defaults.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    /// Returns supported signature schemes for handshake verification.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }

    /// Returns no preferred CA subject hints.
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}
