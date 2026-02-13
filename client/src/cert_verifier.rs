//! Client-side rustls verifier used for Deskheld peer-to-peer trust flow.

use std::sync::Arc;

use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger,
    crypto::{
        CryptoProvider, ring::default_provider, verify_tls12_signature, verify_tls13_signature,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};

/// Certificate verifier that defers trust decisions to post-handshake fingerprinting.
#[derive(Debug)]
pub struct CertVerifier(Arc<CryptoProvider>);

impl CertVerifier {
    /// Creates a new verifier backed by rustls's default crypto provider.
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(default_provider())))
    }
}

impl danger::ServerCertVerifier for CertVerifier {
    /// Accepts server certificates during TLS handshake.
    ///
    /// Actual peer trust checks happen later via certificate fingerprint classification.
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<danger::ServerCertVerified, rustls::Error> {
        Ok(danger::ServerCertVerified::assertion())
    }

    /// Verifies TLS 1.2 handshake signatures using rustls defaults.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
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
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    /// Returns supported signature schemes for handshake verification.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
