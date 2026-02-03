mod cert_verifier;

use std::{io, net::SocketAddr, sync::Arc};

use common::{
    certificate::{self, get_local_identity},
    config::{ALPN_PROTOCOLS, get_config_dir},
    connection::{self, Connection, classify_connection},
};
use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::pki_types::CertificateDer;
use thiserror::Error;

use crate::cert_verifier::CertVerifier;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Failed to create endpoint: {0}")]
    EndpointCreationFailed(io::Error),

    #[error("Failed to create configuration: {0}")]
    ConfigurationFailed(rustls::Error),

    #[error("No valid certificate could be foudn or generated")]
    InvalidCertificate(#[from] certificate::CertificateError),

    #[error("No initial Cypher Suite: {0}")]
    NoInitialCipherSuite(#[from] quinn::crypto::rustls::NoInitialCipherSuite),

    #[error("Outgoing connection failed: {0}")]
    OutgoingConnectionFailed(#[from] quinn::ConnectError),

    #[error("Connection failed: {0}")]
    ConnectionFailed(#[from] quinn::ConnectionError),

    #[error("Certificate couldn't be converted to DER format")]
    CertificateDerConversionFailed,

    #[error("No cryptographic identity provided by peer")]
    NoCryptographicPeerIdentity,

    #[error("Connection classification failed")]
    ConnectionClassificationFailed(#[from] connection::ConnectionError),
}

pub struct Client {
    endpoint: Endpoint,
    cert: Arc<CertificateDer<'static>>,
    dir: std::path::PathBuf,
}

impl Client {
    pub fn new(
        common_name: &str,
        domain_name: &str,
        socket_address: SocketAddr,
    ) -> Result<Self, ClientError> {
        let config_dir = get_config_dir().join("client");
        let (cert, key) = get_local_identity(common_name, domain_name, &config_dir)?;

        let cert_chain = vec![cert.clone()];
        let mut rustls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(CertVerifier::new())
            .with_client_auth_cert(cert_chain, key)
            .map_err(ClientError::ConfigurationFailed)?;
        rustls_config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|&x| x.to_vec()).collect();

        let client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_config)?));

        let mut endpoint =
            Endpoint::client(socket_address).map_err(ClientError::EndpointCreationFailed)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            cert: Arc::new(cert),
            dir: config_dir.to_path_buf(),
        })
    }

    pub async fn connect_to(
        &self,
        server_address: SocketAddr,
        server_name: &str,
    ) -> Result<Connection, ClientError> {
        let connection = self.endpoint.connect(server_address, server_name)?.await?;

        Ok(classify_connection(connection, &self.cert, &self.dir)?)
    }
}
