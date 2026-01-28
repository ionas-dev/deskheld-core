use std::{error::Error, io::stdin, sync::Arc};

use deskheld::common::{
    certificate::{
        calculate_fingerprint, generate_and_save_self_signed_cert, load_identity,
        save_trusted_certificate, set_config_dir_sub, validate_certificate_der,
    },
    config::{CLIENT_ADDR, CLIENT_NAME, SERVER_ADDR, SERVER_NAME},
};
use quinn::{ClientConfig, crypto::rustls::NoInitialCipherSuite};
use quinn::{Endpoint, crypto::rustls::QuicClientConfig};
use rustls::{
    CertificateError::{self},
    DigitallySignedStruct,
    Error::InvalidCertificate,
    SignatureScheme,
    client::danger,
    crypto::{
        CryptoProvider,
        ring::{self, default_provider},
        verify_tls12_signature, verify_tls13_signature,
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug)]
struct CertVerifier(Arc<CryptoProvider>);

impl CertVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(ring::default_provider())))
    }
}

impl danger::ServerCertVerifier for CertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<danger::ServerCertVerified, rustls::Error> {
        println!("Verifying server certificate...");
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

        Ok(danger::ServerCertVerified::assertion())
    }

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

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn client(
    client_config: ClientConfig,
    cert_der: &CertificateDer<'static>,
) -> Result<(), Box<dyn Error>> {
    let endpoint = Endpoint::client(CLIENT_ADDR)?;

    println!("Connecting to server: '{}'", SERVER_ADDR);
    let connection = endpoint
        .connect_with(client_config, SERVER_ADDR, SERVER_NAME)?
        .await?;
    println!(
        "Quarantine connection to server established. You still need to verify the fingerprint!"
    );

    let certs = connection
        .peer_identity()
        .unwrap()
        .downcast::<Vec<CertificateDer>>()
        .unwrap();
    let peer_cert = &certs[0];

    let (_, x509) = X509Certificate::from_der(peer_cert)
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;

    let peer_name = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap();

    let valid = validate_certificate_der(&peer_cert, &peer_name);
    if !valid {
        calculate_fingerprint(vec![peer_cert.clone(), cert_der.clone()]);
        println!("Is this the same fingerprint shown on the server? (y/n)");

        let mut input = String::new();
        stdin().read_line(&mut input).unwrap();
        if input.trim().to_lowercase() != "y" {
            return Err("Certificate verification failed by user".into());
        }
        save_trusted_certificate(&peer_cert, &peer_name).unwrap();
    }
    // Now that the connection is verified, you can use it to send and receive data.
    println!("Connection established and verified :)");

    Ok(())
}

fn configure_client(
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
) -> Result<ClientConfig, NoInitialCipherSuite> {
    let cert_chain = vec![cert_der];
    let mut client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(CertVerifier::new())
        .with_client_auth_cert(cert_chain, key_der)
        .unwrap();
    client_config.alpn_protocols = vec![b"deskheld".to_vec()];

    Ok(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        client_config,
    )?)))
}

#[tokio::main]
async fn main() {
    println!("Start client...");
    default_provider()
        .install_default()
        .expect("Failed to install crypto provider");
    set_config_dir_sub("client");

    let (cert_der, key_der) = load_identity()
        .unwrap_or_else(|_| generate_and_save_self_signed_cert("mac-client", CLIENT_NAME).unwrap());
    let client_config = configure_client(cert_der.clone(), key_der.clone_key()).unwrap();
    client(client_config, &cert_der).await.unwrap();
}
