use log::{debug, warn};
use rcgen::string::Ia5String;
use rcgen::{Certificate, CertificateParams, DnType, KeyPair, SanType};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::fs;
use std::path::Path;
use std::str::FromStr;

use x509_parser::prelude::{FromDer, X509Certificate};

const IDENTITY_CERT_FILENAME: &str = "identity.crt";
const IDENTITY_KEY_FILENAME: &str = "identity.key";
const TRUSTED_DEVICES_FILENAME: &str = "trusted_devices.json";

#[derive(thiserror::Error, Debug)]
pub enum CertificateError {
    #[error("Invalid certificate: {0}")]
    ParsingCertificateFailed(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),

    #[error("Certificate has no common name")]
    NoCommonNameError,

    #[error("Could not parse certificate file: {0}")]
    ParsingCertificateFileFailed(rustls::pki_types::pem::Error),

    #[error("Could not parse private key file: {0}")]
    ParsingPrivateKeyFileFailed(rustls::pki_types::pem::Error),

    #[error("Invalid IA5 String: {0}")]
    InvalidIa5String(rcgen::Error),

    #[error("Generating key pair failed: {0}")]
    GeneratingKeyPairFailed(rcgen::Error),

    #[error("Signing certificate failed: {0}")]
    SigningCertificateFailed(rcgen::Error),

    #[error("Writing identity to file failed: {0}")]
    WritingIdentityToFileFailed(std::io::Error),

    #[error("Reading trusted devices file failed: {0}")]
    ReadingTrustedDevicesFileFailed(std::io::Error),

    #[error("Parsing trusted devices file failed: {0}")]
    ParsingTrustedDevicesFileFailed(serde_json::Error),

    #[error("Serializing trusted devices failed: {0}")]
    SerializingTrustedDevicesFailed(serde_json::Error),

    #[error("Writing trusted devices failed: {0}")]
    WritingTrustedDevicesFailed(std::io::Error),
}

#[derive(Serialize, Deserialize, Debug)]
struct TrustedDevice {
    pub name: String,
    pub cert_sha2: String,
}

pub fn get_local_identity(
    common_name: &str,
    domain_name: &str,
    dir: &Path,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), CertificateError> {
    debug!(
        "Getting local identity for domain: '{}', with common name: '{}'",
        domain_name, common_name
    );

    match load_local_identity(&dir) {
        Ok(Some(identity)) => Ok(identity),
        Ok(None) => {
            let (cert, key_pair) = generate_identity(common_name, domain_name)?;
            save_identity(&cert, &key_pair, &dir)?;
            // Vielleicht klappt die Umwandlung nicht
            Ok((CertificateDer::from(cert), PrivateKeyDer::from(key_pair)))
        }
        Err(e) => {
            warn!(
                "Failed to load identity, even though files for it exist: {}",
                e
            );
            let (cert, key_pair) = generate_identity(common_name, domain_name)?;
            save_identity(&cert, &key_pair, &dir)?;
            Ok((CertificateDer::from(cert), PrivateKeyDer::from(key_pair)))
        }
    }
}

fn load_local_identity(
    dir: &Path,
) -> Result<Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>, CertificateError> {
    let cert_path = dir.join(IDENTITY_CERT_FILENAME);
    let key_path = dir.join(IDENTITY_KEY_FILENAME);

    debug!(
        "Loading local identity certificate and key from:\ncert: '{}'\nkey: '{}'",
        cert_path.display(),
        key_path.display()
    );

    if !cert_path.exists() || !key_path.exists() {
        debug!("No existing identity certificate or key found");
        return Ok(None);
    }

    let cert_der = CertificateDer::from_pem_file(cert_path)
        .map_err(CertificateError::ParsingCertificateFileFailed)?;

    let key_der = PrivatePkcs8KeyDer::from_pem_file(key_path)
        .map_err(CertificateError::ParsingPrivateKeyFileFailed)?;

    Ok(Some((cert_der, PrivateKeyDer::from(key_der))))
}

fn generate_identity(
    common_name: &str,
    domain_name: &str,
) -> Result<(Certificate, KeyPair), CertificateError> {
    debug!(
        "Generating self-signed certificate for domain: '{}', with common name: '{}'",
        domain_name, common_name
    );
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name.to_string());

    params.subject_alt_names.push(SanType::DnsName(
        Ia5String::from_str(domain_name).map_err(CertificateError::InvalidIa5String)?,
    ));

    let key_pair = KeyPair::generate().map_err(CertificateError::GeneratingKeyPairFailed)?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(CertificateError::SigningCertificateFailed)?;

    Ok((cert, key_pair))
}

fn save_identity(cert: &Certificate, key: &KeyPair, dir: &Path) -> Result<(), CertificateError> {
    let cert_path = dir.join(IDENTITY_CERT_FILENAME);
    let key_path = dir.join(IDENTITY_KEY_FILENAME);

    debug!(
        "Saving identity certificate and key to:\ncert: '{}'\nkey: '{}'",
        cert_path.display(),
        key_path.display()
    );

    // TOOD: Ordner erstellen, falls er nicht existiert
    let cert_pem = cert.pem();
    fs::write(&cert_path, cert_pem).map_err(CertificateError::WritingIdentityToFileFailed)?;

    let key_pem = key.serialize_pem();
    fs::write(&key_path, key_pem).map_err(CertificateError::WritingIdentityToFileFailed)?;

    Ok(())
}

pub fn calculate_fingerprint(certs: Vec<&CertificateDer>) -> String {
    debug!(
        "Calculating SHA-256 fingerprint for {} certificates...",
        certs.len()
    );
    let mut certs = certs;

    certs.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));

    let mut hasher = Sha256::new();
    for cert in &certs {
        hasher.update(cert);
    }
    let result = hasher.finalize();

    let fingerprint = format!(
        "{:06}",
        u32::from_be_bytes([result[0], result[1], result[2], result[3]]) % 1000000
    );
    debug!("Calculated fingerprint: {}", fingerprint);
    fingerprint
}

pub fn is_trusted_certificate(
    cert: &CertificateDer,
    fingerprint: &str,
    dir: &Path,
) -> Result<bool, CertificateError> {
    let (_, x509_certificate) = X509Certificate::from_der(cert)?;

    let peer_name = x509_certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .ok_or(CertificateError::NoCommonNameError)?;

    debug!(
        "Checking if certificate with common name '{}' is trusted",
        peer_name
    );

    let Some(device) = load_trusted_certificates(dir)?
        .and_then(|devices| devices.into_iter().find(|d| d.name == peer_name))
    else {
        debug!("No trusted device found with common name '{}'", peer_name);
        return Ok(false);
    };

    let is_trusted = device.cert_sha2 == fingerprint;

    if is_trusted {
        debug!("Certificate with common name '{}' is trusted", peer_name);
    } else {
        warn!(
            "Found a trusted device with common name '{}', but fingerprint does not match!\nStored: '{}', got: '{}'",
            peer_name, device.cert_sha2, fingerprint
        );
    }

    Ok(is_trusted)
}

pub fn save_trusted_certificate(
    cert: &CertificateDer<'_>,
    fingerprint: &str,
    dir: &Path,
) -> Result<(), CertificateError> {
    let trusted_devices_path = dir.join(TRUSTED_DEVICES_FILENAME);

    let (_, x509_certificate) = X509Certificate::from_der(cert)?;

    let peer_name = x509_certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .ok_or(CertificateError::NoCommonNameError)?;

    debug!(
        "Saving trusted certificate for device: '{}' in '{}'",
        peer_name,
        trusted_devices_path.display()
    );

    let mut trusted_devices = load_trusted_certificates(dir)?.unwrap_or(Vec::new());
    let new_device = TrustedDevice {
        name: peer_name.to_string(),
        cert_sha2: fingerprint.to_string(),
    };
    trusted_devices.push(new_device);

    let trusted_devices_data = serde_json::to_string_pretty(&trusted_devices)
        .map_err(CertificateError::SerializingTrustedDevicesFailed)?;
    fs::write(&trusted_devices_path, trusted_devices_data)
        .map_err(CertificateError::WritingTrustedDevicesFailed)?;

    Ok(())
}

fn load_trusted_certificates(dir: &Path) -> Result<Option<Vec<TrustedDevice>>, CertificateError> {
    let trusted_devices_path = dir.join(TRUSTED_DEVICES_FILENAME);

    debug!(
        "Loading trusted devices from '{}'",
        trusted_devices_path.display()
    );

    if !trusted_devices_path.exists() {
        debug!("No trusted devices file found, returning empty list");
        return Ok(None);
    }

    let trusted_devices_data = fs::read_to_string(&trusted_devices_path)
        .map_err(CertificateError::ReadingTrustedDevicesFileFailed)?;
    Ok(Some(
        serde_json::from_str::<Vec<TrustedDevice>>(&trusted_devices_data)
            .map_err(CertificateError::ParsingTrustedDevicesFileFailed)?,
    ))
}
