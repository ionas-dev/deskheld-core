# deskheld

### server

```rust
struct Server {
    acceptedConnections: Arc<RwLock<HashMap<String, AcceptedConnection>>>,
    quarantinedConnections: Arc<RwLock<HashMap<String, QuarantineConnection>>>,
    endpoint: quinn::Endpoint,
}

impl Server {
    pub async fn openServer() -> Result<(Server, Stream<Arc<QuaratineConnection>>, Stream<Arc<AcceptedConnection>>), ServerError>;
    pub fn closeServer(&mut self) -> Result<(), ServerError>;
    pub fn closeConnection(&mut self, connection_id: Arc<QuaratineConnection>) -> Result<(), ServerError>;
    pub fn acceptConnection(&mut self, connection: Arc<QuarantineConnection>) -> Result<Arc<AcceptedConnection>, ServerError>;
    pub fn rejectConnection(&mut self, connection: Arc<QuarantineConnection>) -> Result<(), ServerError>;
}

impl Peer for Server {
    fn config_path(&self) -> &'static Path {
        Path::new("./config/server")
    }
}
```

### common::peer

```rust
pub trait Peer {
    fn config_path(&self) -> &'static Path;
}
```

### certificate

```rust
pub fn get_identity_for(&peer: &Peer) -> Result<(CertificateDer, PrivateKeyDer), CertificateError>;
pub fn let_peer_verify_identity_for_domain(&peer: &Peer, cert: &CertificateDer, domain: &str) -> Result<(), CertificateError>;

```

### connection

```rust

trait Connection {
    pub fn id(&self) -> &str;
    pub fn fingerprint(&self) -> &str;
}

pub struct QuaratineConnection {
    fingerprint: String,
    connection: quinn::Connection,
}

impl QuaratineConnection {
    // Accepts a quarantined connection
    pub fn accept(&mut self) -> Result<(), ConnectionError>;

    // Rejects a quarantined connection
    pub fn reject(&self) -> Result<(), ConnectionError>;
}

impl Connection for QuaratineConnection {
    fn id(&self) -> &String {
        &self.fingerprint
    }

    fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

pub struct AcceptedConnection {
    fingerprint: String,
    connection: quinn::Connection,
}

impl AcceptedConnection {
    pub async fn open_bi_stream(&self) -> Result<(quinn::SendStream, quinn::RecvStream), ServerError> {
        self.connection.open_bi().await.map_err(|_| ServerError::StreamError)
    }
}

impl Connection for AcceptedConnection {
    fn id(&self) -> &String {
        &self.fingerprint
    }

    fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}
```
