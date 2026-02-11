use std::{net::SocketAddr, sync::Arc};

use ::client as inner_client;
use ::server as inner_server;
use common::connection as inner_connection;
use thiserror::Error;
use tokio::sync::{Mutex, mpsc::Receiver};

#[derive(Debug, Clone, uniffi::Record)]
pub struct ResolvedService {
    pub fullname: String,
    pub host_name: String,
    pub addresses: Vec<String>,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum ConnectionStatus {
    Quarantined,
    Accepted,
}

enum ConnectionInner {
    Quarantined(Arc<inner_connection::QuarantineConnection>),
    Accepted(Arc<inner_connection::AcceptedConnection>),
}

#[derive(uniffi::Object)]
pub struct Connection {
    inner: Mutex<ConnectionInner>,
}

#[uniffi::export]
impl Connection {
    pub fn status(&self) -> ConnectionStatus {
        let inner = self.inner.blocking_lock();
        match &*inner {
            ConnectionInner::Quarantined(_) => ConnectionStatus::Quarantined,
            ConnectionInner::Accepted(_) => ConnectionStatus::Accepted,
        }
    }

    pub fn fingerprint(&self) -> String {
        let inner = self.inner.blocking_lock();
        match &*inner {
            ConnectionInner::Quarantined(conn) => conn.fingerprint().to_string(),
            ConnectionInner::Accepted(conn) => conn.fingerprint().to_string(),
        }
    }

    pub fn accept(&self) -> Result<(), ConnectionError> {
        let mut inner = self.inner.blocking_lock();

        if let ConnectionInner::Quarantined(quarantine) = &*inner {
            let accepted = quarantine.accept().map_err(ConnectionError::from)?;
            *inner = ConnectionInner::Accepted(Arc::new(accepted));
        }

        Ok(())
    }

    pub fn reject(&self) {
        let inner = self.inner.blocking_lock();
        if let ConnectionInner::Quarantined(quarantine) = &*inner {
            quarantine.reject();
        }
    }
}

fn map_connection(connection: inner_connection::Connection) -> Arc<Connection> {
    let inner = match connection {
        inner_connection::Connection::Quarantined(connection) => {
            ConnectionInner::Quarantined(connection)
        }
        inner_connection::Connection::Accepted(connection) => ConnectionInner::Accepted(connection),
    };

    Arc::new(Connection {
        inner: Mutex::new(inner),
    })
}

#[derive(Debug, Error, uniffi::Error)]
pub enum ConnectionError {
    #[error("Failed to open stream: {0}")]
    OpeningStreamFailed(String),

    #[error("No cryptographic identity provided by peer")]
    NoCryptographicPeerIdentity,

    #[error("Certificate couldn't be converted to DER format")]
    CertificateDerConversionFailed,

    #[error("Certificate couldn't be verified")]
    CertificateVerificationFailed(String),

    #[error("Failed to save trusted certificate")]
    SavingCertificateFailed(String),
}

impl From<inner_connection::ConnectionError> for ConnectionError {
    fn from(value: inner_connection::ConnectionError) -> Self {
        match value {
            inner_connection::ConnectionError::OpeningStreamFailed(err) => {
                Self::OpeningStreamFailed(err.to_string())
            }
            inner_connection::ConnectionError::NoCryptographicPeerIdentity => {
                Self::NoCryptographicPeerIdentity
            }
            inner_connection::ConnectionError::CertificateDerConversionFailed => {
                Self::CertificateDerConversionFailed
            }
            inner_connection::ConnectionError::CertificateVerificationFailed(err) => {
                Self::CertificateVerificationFailed(err.to_string())
            }
            inner_connection::ConnectionError::SavingCertificateFailed(err) => {
                Self::SavingCertificateFailed(err.to_string())
            }
        }
    }
}

#[derive(Debug, Error, uniffi::Error)]
pub enum ClientError {
    #[error("Failed to create endpoint: {0}")]
    EndpointCreationFailed(String),

    #[error("Failed to create configuration: {0}")]
    ConfigurationFailed(String),

    #[error("No valid certificate could be foudn or generated")]
    InvalidCertificate(String),

    #[error("No initial Cypher Suite: {0}")]
    NoInitialCipherSuite(String),

    #[error("Outgoing connection failed: {0}")]
    OutgoingConnectionFailed(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Certificate couldn't be converted to DER format")]
    CertificateDerConversionFailed,

    #[error("No cryptographic identity provided by peer")]
    NoCryptographicPeerIdentity,

    #[error("Connection classification failed")]
    ConnectionClassificationFailed(String),

    #[error("Failed to create mDNS deamon: {0}")]
    CreatingMDNSDaemonFailed(String),

    #[error("Failed to browse mDNS services: {0}")]
    BrowsingMDNSFailed(String),

    #[error("Failed to receive mDNS service event: {0}")]
    ReceivingMDNSEventFailed(String),
}

impl From<inner_client::ClientError> for ClientError {
    fn from(value: inner_client::ClientError) -> Self {
        match value {
            inner_client::ClientError::EndpointCreationFailed(err) => {
                Self::EndpointCreationFailed(err.to_string())
            }
            inner_client::ClientError::ConfigurationFailed(err) => {
                Self::ConfigurationFailed(err.to_string())
            }
            inner_client::ClientError::InvalidCertificate(err) => {
                Self::InvalidCertificate(err.to_string())
            }
            inner_client::ClientError::NoInitialCipherSuite(err) => {
                Self::NoInitialCipherSuite(err.to_string())
            }
            inner_client::ClientError::OutgoingConnectionFailed(err) => {
                Self::OutgoingConnectionFailed(err.to_string())
            }
            inner_client::ClientError::ConnectionFailed(err) => {
                Self::ConnectionFailed(err.to_string())
            }
            inner_client::ClientError::CertificateDerConversionFailed => {
                Self::CertificateDerConversionFailed
            }
            inner_client::ClientError::NoCryptographicPeerIdentity => {
                Self::NoCryptographicPeerIdentity
            }
            inner_client::ClientError::ConnectionClassificationFailed(err) => {
                Self::ConnectionClassificationFailed(err.to_string())
            }
            inner_client::ClientError::CreatingMDNSDaemonFailed(err) => {
                Self::CreatingMDNSDaemonFailed(err.to_string())
            }
            inner_client::ClientError::BrowsingMDNSFailed(err) => {
                Self::BrowsingMDNSFailed(err.to_string())
            }
            inner_client::ClientError::ReceivingMDNSEventFailed(err) => {
                Self::ReceivingMDNSEventFailed(err.to_string())
            }
        }
    }
}

#[derive(Debug, Error, uniffi::Error)]
pub enum ServerError {
    #[error("TLS Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Too many incoming connections: {0}")]
    TooManyConnections(String),

    #[error("Failed to create endpoint: {0}")]
    EndpointCreationFailed(String),

    #[error("Failed to create configuration: {0}")]
    ConfigurationFailed(String),

    #[error("No initial Cypher Suite: {0}")]
    NoInitialCipherSuite(String),

    #[error("No valid certificate could be found or generated")]
    InvalidCertificate(String),

    #[error("Connection classification failed")]
    ConnectionClassificationFailed(String),

    #[error("Failed to publish service: {0}")]
    CreatingMDNSDeamonFailed(String),

    #[error("Failed to create mDNS service: {0}")]
    CreatingServiceFailed(String),

    #[error("Failed to retrieve local port: {0}")]
    RetrievingLocalPortFailed(String),

    #[error("Failed to retrieve local IP: {0}")]
    RetrievingLocalIpFailed(String),

    #[error("Failed to register mDNS service: {0}")]
    RegisterMDSFailed(String),
}

impl From<inner_server::ServerError> for ServerError {
    fn from(value: inner_server::ServerError) -> Self {
        match value {
            inner_server::ServerError::HandshakeFailed(err) => {
                Self::HandshakeFailed(err.to_string())
            }
            inner_server::ServerError::TooManyConnections(err) => {
                Self::TooManyConnections(err.to_string())
            }
            inner_server::ServerError::EndpointCreationFailed(err) => {
                Self::EndpointCreationFailed(err.to_string())
            }
            inner_server::ServerError::ConfigurationFailed(err) => {
                Self::ConfigurationFailed(err.to_string())
            }
            inner_server::ServerError::NoInitialCipherSuite(err) => {
                Self::NoInitialCipherSuite(err.to_string())
            }
            inner_server::ServerError::InvalidCertificate(err) => {
                Self::InvalidCertificate(err.to_string())
            }
            inner_server::ServerError::ConnectionClassificationFailed(err) => {
                Self::ConnectionClassificationFailed(err.to_string())
            }
            inner_server::ServerError::CreatingMDNSDeamonFailed(err) => {
                Self::CreatingMDNSDeamonFailed(err.to_string())
            }
            inner_server::ServerError::CreatingServiceFailed(err) => {
                Self::CreatingServiceFailed(err.to_string())
            }
            inner_server::ServerError::RetrievingLocalPortFailed(err) => {
                Self::RetrievingLocalPortFailed(err.to_string())
            }
            inner_server::ServerError::RetrievingLocalIpFailed(err) => {
                Self::RetrievingLocalIpFailed(err.to_string())
            }
            inner_server::ServerError::RegisterMDSFailed(err) => {
                Self::RegisterMDSFailed(err.to_string())
            }
        }
    }
}

fn parse_socket_addr_for_client(value: String) -> Result<SocketAddr, ClientError> {
    value
        .parse::<SocketAddr>()
        .map_err(|err| ClientError::EndpointCreationFailed(err.to_string()))
}

fn parse_socket_addr_for_server(value: String) -> Result<SocketAddr, ServerError> {
    value
        .parse::<SocketAddr>()
        .map_err(|err| ServerError::EndpointCreationFailed(err.to_string()))
}

#[derive(uniffi::Object)]
pub struct ResolvedServiceReceiver {
    inner: Mutex<Receiver<Box<mdns_sd::ResolvedService>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl ResolvedServiceReceiver {
    pub async fn recv(&self) -> Option<ResolvedService> {
        let mut receiver = self.inner.lock().await;
        receiver.recv().await.map(|service| ResolvedService {
            fullname: service.fullname.clone(),
            host_name: service.get_hostname().to_string(),
            addresses: service
                .get_addresses()
                .iter()
                .map(|address| address.to_string())
                .collect(),
            port: service.get_port(),
        })
    }
}

#[derive(uniffi::Object)]
pub struct ConnectionReceiver {
    inner: Mutex<Receiver<Result<inner_connection::Connection, inner_server::ServerError>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl ConnectionReceiver {
    pub async fn recv(&self) -> Result<Option<Arc<Connection>>, ServerError> {
        let mut receiver = self.inner.lock().await;

        let item = receiver.recv().await;
        let Some(item) = item else {
            return Ok(None);
        };

        let connection = item.map_err(ServerError::from)?;
        Ok(Some(map_connection(connection)))
    }
}

#[derive(uniffi::Record)]
pub struct ServerOpenResult {
    pub server: Arc<Server>,
    pub connections: Arc<ConnectionReceiver>,
}

#[derive(uniffi::Object)]
pub struct Client {
    inner: inner_client::Client,
}

#[uniffi::export(async_runtime = "tokio")]
impl Client {
    #[uniffi::constructor]
    pub fn new(
        common_name: String,
        domain_name: String,
        socket_address: String,
    ) -> Result<Arc<Self>, ClientError> {
        let socket_address = parse_socket_addr_for_client(socket_address)?;
        let inner = inner_client::Client::new(&common_name, &domain_name, socket_address)
            .map_err(ClientError::from)?;

        Ok(Arc::new(Self { inner }))
    }

    pub fn find_server(&self) -> Result<Arc<ResolvedServiceReceiver>, ClientError> {
        let receiver = self.inner.find_server().map_err(ClientError::from)?;

        Ok(Arc::new(ResolvedServiceReceiver {
            inner: Mutex::new(receiver),
        }))
    }

    pub async fn connect_to(
        &self,
        server_address: String,
        server_name: String,
    ) -> Result<Arc<Connection>, ClientError> {
        let server_address = parse_socket_addr_for_client(server_address)?;

        let connection = self
            .inner
            .connect_to(server_address, &server_name)
            .await
            .map_err(ClientError::from)?;

        Ok(map_connection(connection))
    }
}

#[derive(uniffi::Object)]
pub struct Server {
    inner: Arc<inner_server::Server>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Server {
    #[uniffi::constructor]
    pub fn new(
        instance_name: String,
        host_name: String,
        socket_address: String,
    ) -> Result<Arc<Self>, ServerError> {
        let socket_address = parse_socket_addr_for_server(socket_address)?;
        let inner = inner_server::Server::new(&instance_name, &host_name, socket_address)
            .map_err(ServerError::from)?;

        Ok(Arc::new(Self {
            inner: Arc::new(inner),
        }))
    }

    pub fn open(
        instance_name: String,
        host_name: String,
        server_address: String,
    ) -> Result<ServerOpenResult, ServerError> {
        let server_address = parse_socket_addr_for_server(server_address)?;
        let (inner, connections) =
            inner_server::Server::open(&instance_name, &host_name, server_address)
                .map_err(ServerError::from)?;

        Ok(ServerOpenResult {
            server: Arc::new(Self { inner }),
            connections: Arc::new(ConnectionReceiver {
                inner: Mutex::new(connections),
            }),
        })
    }

    pub fn close(&self) {
        self.inner.close();
    }

    pub fn publish_service(&self) -> Result<(), ServerError> {
        self.inner.publish_service().map_err(ServerError::from)
    }
}

uniffi::setup_scaffolding!();
