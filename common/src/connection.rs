use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use log::debug;
use quinn::{RecvStream, SendStream, VarInt};
use rustls::pki_types::CertificateDer;
use thiserror::Error;

use crate::certificate::{
    self, calculate_fingerprint, is_trusted_certificate, save_trusted_certificate,
};

const REJECTED_CONNECTION_MESSAGE: &str = "Connection rejected";
const REJECTED_CONNECTION_CODE: VarInt = VarInt::from_u32(0x0);

#[derive(Error, Debug)]
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

pub enum Connection {
    Quarantined(Arc<QuarantineConnection>),
    Accepted(Arc<AcceptedConnection>),
}

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

pub struct QuarantineConnection {
    fingerprint: String,
    connection: quinn::Connection,
    certificate: Arc<CertificateDer<'static>>,
    dir: PathBuf,
}

impl QuarantineConnection {
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

    /// Accepts a quarantined connection
    pub fn accept(&self) -> Result<AcceptedConnection, ConnectionError> {
        save_trusted_certificate(&self.certificate, &self.fingerprint, &self.dir)
            .map_err(ConnectionError::SavingCertificateFailed)?;

        Ok(AcceptedConnection {
            fingerprint: self.fingerprint.clone(),
            connection: self.connection.clone(),
            certificate: self.certificate.clone(),
            dir: self.dir.clone(),
        })
    }

    /// Rejects a quarantined connection
    pub fn reject(&self) {
        self.connection.close(
            REJECTED_CONNECTION_CODE,
            REJECTED_CONNECTION_MESSAGE.as_bytes(),
        );
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

pub struct AcceptedConnection {
    fingerprint: String,
    pub connection: quinn::Connection,
    // TODO: Make public
    certificate: Arc<CertificateDer<'static>>,
    dir: std::path::PathBuf,
}

impl AcceptedConnection {
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

    pub async fn open_bi_stream(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let (send_stream, recv_stream) = self.connection.open_bi().await?;
        Ok((send_stream, recv_stream))
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}
