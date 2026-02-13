//! Connection classification and wrapper types shared between server and client.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use log::debug;
use quinn::{RecvStream, SendStream, VarInt};
use rustls::pki_types::CertificateDer;

use crate::certificate::{
    self, calculate_fingerprint, is_trusted_certificate, save_trusted_certificate,
};

const REJECTED_CONNECTION_MESSAGE: &str = "Connection rejected";
const REJECTED_CONNECTION_CODE: VarInt = VarInt::from_u32(0x0);

/// Errors produced while classifying, accepting, or operating on QUIC connections.
#[derive(thiserror::Error, Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum ConnectionError {
    #[error("Failed to open stream: {0}")]
    OpeningStreamFailed(#[from] quinn::ConnectionError),

    #[error("No cryptographic identity provided by peer")]
    NoCryptographicPeerIdentity,

    #[error("Certificate couldn't be converted to DER format")]
    CertificateDerConversionFailed,

    #[error("Certificate couldn't be verified")]
    CertificateVerificationFailed(certificate::CertificateError),

    #[error("Failed to save trusted certificate")]
    SavingCertificateFailed(certificate::CertificateError),
}

/// Connection state after trust classification.
#[derive(uniffi::Enum)]
pub enum Connection {
    /// A connection from an unknown or untrusted peer certificate.
    Quarantined(Arc<QuarantineConnection>),
    /// A connection with a trusted peer certificate.
    Accepted(Arc<AcceptedConnection>),
}

/// Classifies a QUIC connection as accepted or quarantined based on peer trust.
pub fn classify_connection(
    connection: quinn::Connection,
    local_cert: &CertificateDer,
    dir: &Path,
) -> Result<Connection, ConnectionError> {
    let peer_cert = &connection
        .peer_identity()
        .ok_or(ConnectionError::NoCryptographicPeerIdentity)?
        .downcast::<Vec<CertificateDer>>()
        .map_err(|_| ConnectionError::CertificateDerConversionFailed)?[0];

    let certs = vec![peer_cert, local_cert];
    let fingerprint = calculate_fingerprint(certs);

    if is_trusted_certificate(&peer_cert, &fingerprint, &dir)
        .map_err(ConnectionError::CertificateVerificationFailed)?
    {
        debug!(
            "Accepting connection with fingerprint '{}', from '{}'",
            fingerprint,
            connection.remote_address()
        );

        let accepted = Arc::new(AcceptedConnection::new(
            fingerprint,
            connection,
            Arc::new(peer_cert.clone()),
            dir.to_path_buf(),
        ));
        Ok(Connection::Accepted(accepted))
    } else {
        debug!(
            "Quarantining connection with fingerprint '{}', from '{}'",
            fingerprint,
            connection.remote_address()
        );

        let quarantine = Arc::new(QuarantineConnection::new(
            fingerprint,
            connection,
            Arc::new(peer_cert.clone()),
            dir.to_path_buf(),
        ));
        Ok(Connection::Quarantined(quarantine))
    }
}

/// QUIC connection wrapper for peers that have not been explicitly trusted yet.
#[derive(uniffi::Object)]
pub struct QuarantineConnection {
    fingerprint: String,
    connection: quinn::Connection,
    certificate: Arc<CertificateDer<'static>>,
    dir: PathBuf,
}

#[uniffi::export]
impl QuarantineConnection {
    /// Accepts a quarantined connection and converts it to an accepted connection.
    ///
    /// The peer certificate is persisted as trusted for future sessions.
    pub fn accept(&self) -> Result<AcceptedConnection, ConnectionError> {
        save_trusted_certificate(&self.certificate, &self.fingerprint, &self.dir)
            .map_err(ConnectionError::SavingCertificateFailed)?;

        Ok(AcceptedConnection {
            fingerprint: self.fingerprint.clone(),
            connection: self.connection.clone(),
            _certificate: self.certificate.clone(),
            _dir: self.dir.clone(),
        })
    }

    /// Rejects a quarantined connection and closes it.
    pub fn reject(&self) {
        self.connection.close(
            REJECTED_CONNECTION_CODE,
            REJECTED_CONNECTION_MESSAGE.as_bytes(),
        );
    }

    /// UniFFI wrapper for `fingerprint()` exposed as `fingerprint` in bindings.
    ///
    /// Returns the combined peer/local certificate pairing fingerprint.
    ///
    /// Rust callers should prefer `QuarantineConnection::fingerprint`.
    #[uniffi::method(name = "fingerprint")]
    pub fn fingerprint_ffi(&self) -> String {
        self.fingerprint.clone()
    }
}

impl QuarantineConnection {
    /// Creates a new quarantined connection wrapper.
    pub fn new(
        fingerprint: String,
        connection: quinn::Connection,
        certificate: Arc<CertificateDer<'static>>,
        dir: PathBuf,
    ) -> Self {
        Self {
            fingerprint,
            connection,
            certificate,
            dir,
        }
    }

    /// Returns the pairing fingerprint for this connection.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// QUIC connection wrapper for peers that were accepted as trusted.
#[derive(uniffi::Object)]
pub struct AcceptedConnection {
    fingerprint: String,
    // TODO: Make private
    pub connection: quinn::Connection,
    _certificate: Arc<CertificateDer<'static>>,
    _dir: std::path::PathBuf,
}

#[uniffi::export]
impl AcceptedConnection {
    /// UniFFI wrapper for `fingerprint()` exposed as `fingerprint` in bindings.
    ///
    /// Rust callers should prefer `AcceptedConnection::fingerprint`.
    #[uniffi::method(name = "fingerprint")]
    pub fn fingerprint_ffi(&self) -> String {
        self.fingerprint.clone()
    }
}

impl AcceptedConnection {
    /// Creates a new accepted connection wrapper.
    pub fn new(
        fingerprint: String,
        connection: quinn::Connection,
        certificate: Arc<CertificateDer<'static>>,
        dir: PathBuf,
    ) -> Self {
        Self {
            fingerprint,
            connection,
            _certificate: certificate,
            _dir: dir,
        }
    }

    /// Opens a bidirectional stream on the underlying QUIC connection.
    pub async fn open_bi_stream(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let (send_stream, recv_stream) = self.connection.open_bi().await?;
        Ok((send_stream, recv_stream))
    }

    /// Returns the pairing fingerprint for this connection.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}
