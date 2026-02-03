mod cert_verifier;

use std::{io, net::SocketAddr, path::PathBuf, sync::Arc};

use common::{
    certificate::{self, get_local_identity},
    config::{ALPN_PROTOCOLS, get_config_dir},
    connection::{self, Connection, classify_connection},
};
use quinn::{Endpoint, ServerConfig, crypto::rustls::QuicServerConfig};
use rustls::pki_types::CertificateDer;
use thiserror::Error;
use tokio::sync::{
    Semaphore,
    mpsc::{self, Receiver},
};

use crate::cert_verifier::CertVerifier;

const NORMAL_SHUTDOWN_CODE: quinn::VarInt = quinn::VarInt::from_u32(0x0);
const NORMAL_SHUTDOWN_MESSAGE: &[u8] = b"Normal shutdown";
const MAX_CONCURRENT_INCOMING_CONNECTIONS: usize = 10;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("TLS Handshake failed: {0}")]
    HandshakeFailed(#[from] quinn::ConnectionError),

    #[error("Too many incoming connections: {0}")]
    TooManyConnections(#[from] tokio::sync::AcquireError),

    #[error("Failed to create endpoint: {0}")]
    EndpointCreationFailed(io::Error),

    #[error("Failed to create configuration: {0}")]
    ConfigurationFailed(rustls::Error),

    #[error("No initial Cypher Suite: {0}")]
    NoInitialCipherSuite(#[from] quinn::crypto::rustls::NoInitialCipherSuite),

    #[error("No valid certificate could be found or generated")]
    InvalidCertificate(#[from] certificate::CertificateError),

    #[error("Connection classification failed")]
    ConnectionClassificationFailed(#[from] connection::ConnectionError),
}

pub struct Server {
    endpoint: quinn::Endpoint,
    cert: Arc<CertificateDer<'static>>,
    dir: PathBuf,
}

impl Server {
    pub fn new(
        common_name: &str,
        domain_name: &str,
        socket_address: SocketAddr,
    ) -> Result<Self, ServerError> {
        let config_dir = get_config_dir().join("server");

        let (cert, key) = get_local_identity(common_name, domain_name, &config_dir)?;
        let cert_chain = vec![cert.clone()];
        let mut rustls_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(CertVerifier::new())
            .with_single_cert(cert_chain, key)
            .map_err(ServerError::ConfigurationFailed)?;
        rustls_config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|&x| x.to_vec()).collect();

        let config =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(rustls_config)?));
        let endpoint = Endpoint::server(config, socket_address)
            .map_err(ServerError::EndpointCreationFailed)?;

        Ok(Self {
            endpoint,
            cert: Arc::new(cert),
            dir: config_dir.to_path_buf(),
        })
    }

    pub fn open(
        common_name: &str,
        domain_name: &str,
        server_address: SocketAddr,
    ) -> Result<(Arc<Self>, Receiver<Result<Connection, ServerError>>), ServerError> {
        let server = Arc::new(Server::new(common_name, domain_name, server_address)?);

        let (sender, receiver) =
            mpsc::channel::<Result<Connection, ServerError>>(MAX_CONCURRENT_INCOMING_CONNECTIONS);
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_INCOMING_CONNECTIONS));

        let endpoint = server.endpoint.clone();
        let local_cert = server.cert.clone();
        let dir = Arc::new(server.dir.clone());
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(permit) = semaphore.clone().acquire_owned().await else {
                    break;
                };

                let sender = sender.clone();
                let local_cert = local_cert.clone();
                let dir = dir.clone();
                tokio::spawn(async move {
                    let _ = permit;

                    let connection =
                        async { Ok(classify_connection(incoming.await?, &local_cert, &dir)?) };

                    sender.send(connection.await).await.ok();
                });
            }
        });

        Ok((server, receiver))
    }

    pub fn close(self: &Arc<Self>) {
        self.endpoint
            .close(NORMAL_SHUTDOWN_CODE, NORMAL_SHUTDOWN_MESSAGE);
    }
}
