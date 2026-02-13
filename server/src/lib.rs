mod cert_verifier;

use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex as StdMutex},
};

use common::{
    certificate::{self, get_local_identity},
    config::{ALPN_PROTOCOLS, SERVICE_TYPE, get_config_dir},
    connection::{self, Connection, classify_connection},
};
use log::{info, warn};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use quinn::{Endpoint, ServerConfig, crypto::rustls::QuicServerConfig};
use rustls::pki_types::CertificateDer;
use tokio::sync::{
    Mutex, Semaphore,
    mpsc::{self, Receiver},
};

use crate::cert_verifier::CertVerifier;

const NORMAL_SHUTDOWN_CODE: quinn::VarInt = quinn::VarInt::from_u32(0x0);
const NORMAL_SHUTDOWN_MESSAGE: &[u8] = b"Normal shutdown";
const MAX_CONCURRENT_INCOMING_CONNECTIONS: usize = 10;

#[derive(thiserror::Error, Debug, uniffi::Error)]
#[uniffi(flat_error)]
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

    #[error("Failed to publish service: {0}")]
    CreatingMDNSDeamonFailed(mdns_sd::Error),

    #[error("Failed to create mDNS service: {0}")]
    CreatingServiceFailed(mdns_sd::Error),

    #[error("Failed to retrieve local port: {0}")]
    RetrievingLocalPortFailed(io::Error),

    #[error("Failed to retrieve local IP: {0}")]
    RetrievingLocalIpFailed(io::Error),

    #[error("Failed to register mDNS service: {0}")]
    RegisterMDSFailed(mdns_sd::Error),

    #[error("Connection closed")]
    ConnectionClosed,
}

#[derive(uniffi::Object)]
pub struct Server {
    endpoint: quinn::Endpoint,
    cert: Arc<CertificateDer<'static>>,
    instance_name: String,
    host_name: String,
    dir: PathBuf,
    mdns: StdMutex<Option<ServiceDaemon>>,
    service_fullname: StdMutex<Option<String>>,
}

#[uniffi::export]
impl Server {
    #[uniffi::constructor]
    pub fn new(
        instance_name: &str,
        host_name: &str,
        socket_address: SocketAddr,
    ) -> Result<Self, ServerError> {
        common::init_rust_logging_from_env_once();
        common::ensure_rustls_ring_provider();

        let config_dir = get_config_dir().join("server");

        let (cert, key) = get_local_identity(instance_name, host_name, &config_dir)?;
        let cert_chain = vec![cert.clone()];
        let mut rustls_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(CertVerifier::new())
            .with_single_cert(cert_chain, key)
            .map_err(ServerError::ConfigurationFailed)?;
        rustls_config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|&x| x.to_vec()).collect();

        let config =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(rustls_config)?));

        let endpoint = common::with_tokio_runtime_context(|| Endpoint::server(config, socket_address))
            .map_err(ServerError::EndpointCreationFailed)?;

        Ok(Self {
            endpoint,
            cert: Arc::new(cert),
            instance_name: instance_name.to_string(),
            host_name: host_name.to_string(),
            dir: config_dir.to_path_buf(),
            mdns: StdMutex::new(None),
            service_fullname: StdMutex::new(None),
        })
    }

    pub fn close(self: &Arc<Self>) {
        self.endpoint
            .close(NORMAL_SHUTDOWN_CODE, NORMAL_SHUTDOWN_MESSAGE);

        let service_fullname = self
            .service_fullname
            .lock()
            .ok()
            .and_then(|mut name| name.take());
        let mdns = self.mdns.lock().ok().and_then(|mut daemon| daemon.take());

        if let Some(mdns) = mdns {
            if let Some(service_fullname) = service_fullname {
                if let Err(error) = mdns.unregister(&service_fullname) {
                    warn!(
                        "Failed to unregister mDNS service '{}': {}",
                        service_fullname, error
                    );
                }
            }
            if let Err(error) = mdns.shutdown() {
                warn!("Failed to shutdown mDNS daemon: {}", error);
            }
        }
    }

    pub fn publish_service(self: &Arc<Self>) -> Result<(), ServerError> {
        if let Ok(daemon) = self.mdns.lock() {
            if daemon.is_some() {
                return Ok(());
            }
        }

        let mdns = ServiceDaemon::new().map_err(ServerError::CreatingMDNSDeamonFailed)?;

        let host_name = format!("{}.local.", self.host_name);
        let port = self
            .endpoint
            .local_addr()
            .map_err(ServerError::RetrievingLocalPortFailed)?
            .port();

        let ip_addr = self
            .endpoint
            .local_addr()
            .map_err(ServerError::RetrievingLocalIpFailed)?
            .ip();

        info!(
            "Publishing mDNS service with name '{}', host '{}', IP '{}', and port '{}'",
            SERVICE_TYPE, host_name, ip_addr, port
        );

        let my_service = ServiceInfo::new(
            SERVICE_TYPE,
            &self.instance_name,
            &host_name,
            ip_addr,
            port,
            None,
        )
        .map_err(ServerError::CreatingServiceFailed)?
        .enable_addr_auto();

        let service_fullname = my_service.get_fullname().to_string();

        mdns.register(my_service).map_err(ServerError::RegisterMDSFailed)?;

        if let Ok(mut name) = self.service_fullname.lock() {
            *name = Some(service_fullname);
        }
        if let Ok(mut daemon) = self.mdns.lock() {
            *daemon = Some(mdns);
        }

        Ok(())
    }

    #[uniffi::method(name = "open")]
    pub fn open_ffi(self: &Arc<Self>) -> Result<ConnectionReceiver, ServerError> {
        let receiver = self.open()?;
        Ok(ConnectionReceiver {
            receiver: Mutex::new(receiver),
        })
    }
}

impl Server {
    pub fn open(
        self: &Arc<Self>,
    ) -> Result<Receiver<Result<Connection, ServerError>>, ServerError> {
        self.publish_service()?;

        let (sender, receiver) =
            mpsc::channel::<Result<Connection, ServerError>>(MAX_CONCURRENT_INCOMING_CONNECTIONS);
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_INCOMING_CONNECTIONS));

        let endpoint = self.endpoint.clone();
        let local_cert = self.cert.clone();
        let dir = Arc::new(self.dir.clone());

        info!(
            "Server is listening on {}",
            endpoint
                .local_addr()
                .map_err(ServerError::EndpointCreationFailed)?,
        );

        common::spawn_task(async move {
            while let Some(incoming) = endpoint.accept().await {
                info!("New incoming connection from {}", incoming.remote_address());

                let Ok(permit) = semaphore.clone().acquire_owned().await else {
                    break;
                };

                let sender = sender.clone();
                let local_cert = local_cert.clone();
                let dir = dir.clone();
                common::spawn_task(async move {
                    let _ = permit;

                    let connection =
                        async { Ok(classify_connection(incoming.await?, &local_cert, &dir)?) };

                    sender.send(connection.await).await.ok();
                });
            }
        });

        Ok(receiver)
    }

    pub fn create_and_open(
        instance_name: &str,
        host_name: &str,
        server_address: SocketAddr,
    ) -> Result<(Arc<Self>, Receiver<Result<Connection, ServerError>>), ServerError> {
        let server = Arc::new(Server::new(instance_name, host_name, server_address)?);
        let receiver = server.open()?;
        Ok((server, receiver))
    }
}

#[derive(uniffi::Object)]
pub struct ConnectionReceiver {
    receiver: Mutex<Receiver<Result<Connection, ServerError>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl ConnectionReceiver {
    pub async fn recv(&self) -> Result<Connection, ServerError> {
        let mut receiver = self.receiver.lock().await;
        receiver.recv().await.ok_or(ServerError::ConnectionClosed)?
    }
}

uniffi::custom_type!(SocketAddr, String, {
    remote,
    lower: |s| s.to_string(),
    try_lift: |s| SocketAddr::from_str(&s).map_err(anyhow::Error::new)
});

uniffi::setup_scaffolding!("DeskheldServer");
