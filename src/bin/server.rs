use std::io::stdin;
use std::{error::Error, sync::Arc};

use deskheld::common::certificate::{
    save_trusted_certificate, set_config_dir_sub, validate_certificate_der,
};
use deskheld::common::{
    certificate::{calculate_fingerprint, generate_and_save_self_signed_cert, load_identity},
    config::{SERVER_ADDR, SERVER_NAME},
};
use quinn::Endpoint;
use quinn::ServerConfig;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::PrivateKeyDer;
use rustls::{
    CertificateError,
    Error::InvalidCertificate,
    crypto::{CryptoProvider, ring::default_provider},
    pki_types::CertificateDer,
    server::danger,
};
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug)]
struct CertVerifier(Arc<CryptoProvider>);

impl CertVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(default_provider())))
    }
}

impl danger::ClientCertVerifier for CertVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<danger::ClientCertVerified, rustls::Error> {
        println!("Verifying client certificate...");
        let x509_cert = match X509Certificate::from_der(end_entity) {
            Ok((_, cert)) => cert,
            Err(e) => {
                println!("Failed to parse certificate with Error: {}", e);
                return Err(InvalidCertificate(CertificateError::BadEncoding));
            }
        };
        if !x509_cert.validity.is_valid() {
            println!("Certificate is not valid at the current time.");
            return Err(InvalidCertificate(CertificateError::Expired));
        }
        // TODO: Namen prüfen

        Ok(danger::ClientCertVerified::assertion())
    }

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

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}

async fn server(
    config: ServerConfig,
    cert_der: &CertificateDer<'static>,
) -> Result<(), Box<dyn Error>> {
    // Bind this endpoint to a UDP socket on the given server address.
    let endpoint = Endpoint::server(config, SERVER_ADDR)?;

    // Start iterating over incoming connections.
    while let Some(conn) = endpoint.accept().await {
        let connection = conn.await?;
        println!(
            "Quarantine connection established to client from: '{}'",
            connection.remote_address()
        );
        println!("You still need to verify the fingerprint!");

        let certs = connection
            .peer_identity()
            .unwrap()
            .downcast::<Vec<CertificateDer>>()
            .unwrap();
        let peer_cert = &certs[0];

        let (_, x509) = X509Certificate::from_der(peer_cert).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        let peer_name = x509
            .subject()
            .iter_common_name()
            .next()
            .and_then(|attr| attr.as_str().ok())
            .unwrap();

        let valid = validate_certificate_der(&peer_cert, &peer_name);
        if !valid {
            calculate_fingerprint(vec![peer_cert.clone(), cert_der.clone()]);
            println!("Is this the same fingerprint shown on the client? (y/n)");

            let mut input = String::new();
            stdin().read_line(&mut input).unwrap();
            if input.trim().to_lowercase() != "y" {
                return Err("Certificate verification failed by user".into());
            }
            save_trusted_certificate(&peer_cert, &peer_name).unwrap();
        }

        // Now that the connection is verified, you can use it to send and receive data.
        println!("Connection established and verified :)");
    }

    Ok(())
}

fn configure_server(
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
) -> Result<ServerConfig, Box<dyn Error>> {
    let cert_chain = vec![cert_der.clone()];
    let mut server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(CertVerifier::new())
        .with_single_cert(cert_chain, key_der)?;
    server_config.alpn_protocols = vec![b"deskheld".to_vec()];

    Ok(ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_config)?,
    )))
}

#[tokio::main]
async fn main() {
    println!("Start server...");
    default_provider()
        .install_default()
        .expect("Failed to install crypto provider");
    set_config_dir_sub("server");

    let (cert_der, key_der) = load_identity()
        .unwrap_or_else(|_| generate_and_save_self_signed_cert("mac-server", SERVER_NAME).unwrap());

    let config = configure_server(cert_der.clone(), key_der.clone_key()).unwrap();
    server(config, &cert_der).await.unwrap();
}
