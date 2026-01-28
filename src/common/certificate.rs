use crate::common::config::{APPLICATION, ORGANIZATION, QUALIFIER};
use directories::ProjectDirs;
use rcgen::string::Ia5String;
use rcgen::{Certificate, CertificateParams, DnType, KeyPair, SanType};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::str::FromStr;
use std::sync::OnceLock;

const CONFIG_DIR_FALLBACK: &str = ".";
const IDENTITY_CERT_FILENAME: &str = "identity.crt";
const IDENTITY_KEY_FILENAME: &str = "identity.key";
const TRUSTED_DEVICES_FILENAME: &str = "trusted_devices.json";

static CONFIG_DIR_SUB: OnceLock<String> = OnceLock::new();

#[derive(Serialize, Deserialize, Debug)]
struct TrustedDevice {
    pub name: String,
    pub cert_sha2: String,
}

pub fn set_config_dir_sub(dir_sub: &str) {
    let _ = CONFIG_DIR_SUB.set(dir_sub.to_string());
}

fn get_config_dir() -> std::path::PathBuf {
    if let Some(proj_dirs) = ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION) {
        let config_dir = proj_dirs.config_dir().join(CONFIG_DIR_SUB.get().unwrap());
        fs::create_dir_all(&config_dir).ok();
        return config_dir;
    }
    std::path::PathBuf::from(CONFIG_DIR_FALLBACK)
}

fn save_identity_cert(cert: &Certificate) {
    let config_dir = get_config_dir();
    let cert_path = config_dir.join(IDENTITY_CERT_FILENAME);
    println!("Saving certificate to: '{}'", cert_path.display());
    fs::write(&cert_path, cert.pem()).unwrap();
    println!("Saved certificate.");
}

fn save_identity_key(signing_key: &KeyPair) {
    let config_dir = get_config_dir();
    let key_path = config_dir.join(IDENTITY_KEY_FILENAME);
    println!("Saving private key to: '{}'", key_path.display());
    fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    println!("Saved private key.");
}

pub fn calculate_fingerprint(mut certs: Vec<CertificateDer>) -> String {
    println!("Calculating SHA-256 fingerprint for certificate DER...");

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
    println!("Calculated fingerprint: {}", fingerprint);
    fingerprint
}

pub fn load_identity() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Box<dyn Error>>
{
    let config_dir = get_config_dir();
    let cert_path = config_dir.join(IDENTITY_CERT_FILENAME);
    let key_path = config_dir.join(IDENTITY_KEY_FILENAME);

    println!(
        "Loading identity certificate and key from:\ncert: '{}'\nkey: '{}'",
        cert_path.display(),
        key_path.display()
    );
    let cert_der = match CertificateDer::from_pem_file(cert_path) {
        Ok(cert) => cert,
        Err(e) => {
            println!("No identity certificate found");
            return Err(Box::new(e));
        }
    };
    let key_der = match PrivatePkcs8KeyDer::from_pem_file(key_path) {
        Ok(key) => key,
        Err(e) => {
            println!("No identity private key found");
            return Err(Box::new(e));
        }
    };
    println!("Loaded identity certificate and key.");

    Ok((cert_der, PrivateKeyDer::from(key_der)))
}

pub fn generate_and_save_self_signed_cert(
    common_name: &str,
    domain_name: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), Box<dyn Error>> {
    println!(
        "Generating self-signed certificate for domain: '{}', with common name: '{}'",
        domain_name, common_name
    );

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
        .subject_alt_names
        .push(SanType::DnsName(Ia5String::from_str(domain_name).unwrap()));
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    println!(
        "Generated self-signed certificate:\n{}\n{}",
        cert.pem(),
        key_pair.public_key_pem()
    );

    save_identity_cert(&cert);
    save_identity_key(&key_pair);

    let cert_der = CertificateDer::from(cert);
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    Ok((cert_der, PrivateKeyDer::from(key_der)))
}

pub fn validate_certificate_der(cert: &CertificateDer<'_>, domain_name: &str) -> bool {
    println!(
        "Validating certificate for domain: '{}' against trusted devices...",
        domain_name
    );

    let config_dir = get_config_dir();
    let trusted_devices_path = config_dir.join(TRUSTED_DEVICES_FILENAME);
    if !trusted_devices_path.exists() {
        println!(
            "No trusted devices file found at '{}'. Skipping certificate validation.",
            trusted_devices_path.display()
        );
        return false;
    }
    let trusted_devices_data = fs::read_to_string(&trusted_devices_path).unwrap();
    let trusted_devices: Vec<TrustedDevice> =
        serde_json::from_str::<Vec<TrustedDevice>>(&trusted_devices_data).unwrap();

    let Some(device) = trusted_devices
        .iter()
        .find(|device| device.name == domain_name)
    else {
        return false;
    };

    let cert_sha2 = calculate_fingerprint(vec![cert.clone()]);
    let valid = cert_sha2 == device.cert_sha2;
    println!("Certificate is{} valid", if valid { "" } else { "not " });

    return valid;
}

pub fn save_trusted_certificate(
    cert: &CertificateDer<'_>,
    domain_name: &str,
) -> Result<(), Box<dyn Error>> {
    let config_dir = get_config_dir();
    let trusted_devices_path = config_dir.join(TRUSTED_DEVICES_FILENAME);
    println!(
        "Saving trusted certificate for device: '{}' in '{}'",
        domain_name,
        trusted_devices_path.display()
    );

    let mut trusted_devices: Vec<TrustedDevice> = if trusted_devices_path.exists() {
        let trusted_devices_data = fs::read_to_string(&trusted_devices_path).unwrap();
        serde_json::from_str::<Vec<TrustedDevice>>(&trusted_devices_data).unwrap()
    } else {
        Vec::new()
    };

    let cert_sha2 = calculate_fingerprint(vec![cert.clone()]);
    let new_device = TrustedDevice {
        name: domain_name.to_string(),
        cert_sha2,
    };
    trusted_devices.push(new_device);

    let trusted_devices_data = serde_json::to_string_pretty(&trusted_devices).unwrap();
    fs::write(&trusted_devices_path, trusted_devices_data).unwrap();
    println!("Saved trusted device.");

    Ok(())
}
