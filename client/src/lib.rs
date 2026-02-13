mod cert_verifier;

use std::{io, net::SocketAddr, str::FromStr, sync::Arc};

use common::{
    certificate::{self, get_local_identity},
    config::{ALPN_PROTOCOLS, SERVICE_TYPE, get_config_dir},
    connection::{self, Connection, classify_connection},
};
use flume::RecvError;
use log::{debug, info};
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent};
use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::pki_types::CertificateDer;
use tokio::sync::{
    Mutex,
    mpsc::{Receiver, channel},
};

use crate::cert_verifier::CertVerifier;

#[derive(thiserror::Error, Debug, uniffi::Error)]
#[uniffi(flat_error)]
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

    #[error("Failed to create mDNS deamon: {0}")]
    CreatingMDNSDaemonFailed(mdns_sd::Error),

    #[error("Failed to browse mDNS services: {0}")]
    BrowsingMDNSFailed(mdns_sd::Error),

    #[error("Failed to receive mDNS service event: {0}")]
    ReceivingMDNSEventFailed(RecvError),

    #[error("No service found")]
    ServiceClosed,
}

#[derive(uniffi::Record)]
pub struct Service {
    pub fullname: String,
    pub hostname: String,
    pub addresses: Vec<String>,
    pub port: u16,
}

impl Service {
    fn from_mdns(service: &ResolvedService) -> Self {
        Self {
            fullname: service.fullname.clone(),
            hostname: service.get_hostname().to_string(),
            addresses: service
                .get_addresses()
                .iter()
                .map(|addr| addr.to_string())
                .collect(),
            port: service.get_port(),
        }
    }

    pub fn first_socket_addr_v4(&self) -> Option<SocketAddr> {
        self.addresses
            .iter()
            .filter_map(|ip| ip.parse().ok())
            .find(|ip: &std::net::IpAddr| ip.is_ipv4())
            .map(|ip| SocketAddr::new(ip, self.port))
    }
}

#[derive(uniffi::Object)]
pub struct ServiceReceiver {
    receiver: Mutex<Receiver<Service>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl ServiceReceiver {
    pub async fn recv(&self) -> Result<Service, ClientError> {
        let mut receiver = self.receiver.lock().await;
        receiver.recv().await.ok_or(ClientError::ServiceClosed)
    }
}

#[derive(uniffi::Object)]
pub struct Client {
    endpoint: Endpoint,
    cert: Arc<CertificateDer<'static>>,
    dir: std::path::PathBuf,
}

#[uniffi::export(async_runtime = "tokio")]
impl Client {
    #[uniffi::constructor]
    pub fn new(
        common_name: &str,
        domain_name: &str,
        socket_address: SocketAddr,
    ) -> Result<Self, ClientError> {
        common::init_rust_logging_from_env_once();
        common::ensure_rustls_ring_provider();

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

        let mut endpoint = common::with_tokio_runtime_context(|| Endpoint::client(socket_address))
            .map_err(ClientError::EndpointCreationFailed)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            cert: Arc::new(cert),
            dir: config_dir.to_path_buf(),
        })
    }

    #[uniffi::method(name = "findServer")]
    pub fn find_server_ffi(&self) -> Result<ServiceReceiver, ClientError> {
        let receiver = self.find_server()?;
        Ok(ServiceReceiver {
            receiver: Mutex::new(receiver),
        })
    }

    pub async fn connect_to(
        &self,
        server_address: SocketAddr,
        server_name: String,
    ) -> Result<Connection, ClientError> {
        let connection = self.endpoint.connect(server_address, &server_name)?.await?;

        Ok(classify_connection(connection, &self.cert, &self.dir)?)
    }
}

impl Client {
    pub fn find_server(&self) -> Result<Receiver<Service>, ClientError> {
        let mdns_daemon = ServiceDaemon::new().map_err(ClientError::CreatingMDNSDaemonFailed)?;
        let mdns_receiver = mdns_daemon
            .browse(SERVICE_TYPE)
            .map_err(ClientError::BrowsingMDNSFailed)?;

        let (sender, receiver) = channel::<Service>(10);

        common::spawn_task(async move {
            let duration = std::time::Duration::from_secs(30);

            let result = tokio::time::timeout(duration, async {
                while let Ok(event) = mdns_receiver.recv_async().await {
                    if let ServiceEvent::ServiceResolved(service) = event {
                        info!("Resolved service: {}", service.fullname);
                        if sender.send(Service::from_mdns(&service)).await.is_err() {
                            break;
                        }
                    }
                }
            })
            .await;

            if result.is_err() {
                debug!("mDNS discovery timed out after {:?}", duration);
            }

            mdns_daemon.shutdown().ok();
            debug!("mDNS daemon closed.");
        });

        Ok(receiver)
    }
}

uniffi::custom_type!(SocketAddr, String, {
    remote,
    lower: |s| s.to_string(),
    try_lift: |s| SocketAddr::from_str(&s).map_err(anyhow::Error::new)
});

uniffi::setup_scaffolding!("DeskheldClient");
