use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use directories::ProjectDirs;

/// Reverse domain qualifier used for platform-specific config directory resolution.
pub const QUALIFIER: &str = "com";
/// Organization identifier used for platform-specific config directory resolution.
pub const ORGANIZATION: &str = "deskheld";
/// Application identifier used for platform-specific config directory resolution.
pub const APPLICATION: &str = "deskheld";

/// Default server TLS host name used in development.
pub const SERVER_NAME: &str = "localhost";
/// Default client TLS host name used in development.
pub const CLIENT_NAME: &str = "localhost";
/// IPv4 localhost address constant.
pub const LOCALHOST_V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// Default client bind address used by examples and bindings.
pub const CLIENT_ADDR: SocketAddr = SocketAddr::new(LOCALHOST_V4, 5000);
/// Default server bind address used by examples and bindings.
pub const SERVER_ADDR: SocketAddr = SocketAddr::new(LOCALHOST_V4, 5001);

/// ALPN protocols accepted by Deskheld QUIC endpoints.
pub const ALPN_PROTOCOLS: &[&[u8]] = &[b"deskheld-sync"];
/// mDNS service type used for server discovery.
pub const SERVICE_TYPE: &str = "_deskheld._udp.local.";

const CONFIG_DIR_FALLBACK: &str = ".";

/// Returns the Deskheld config directory and creates it when possible.
///
/// Falls back to the current working directory when the platform-specific
/// project directory cannot be resolved.
pub fn get_config_dir() -> PathBuf {
    if let Some(proj_dirs) = ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION) {
        let config_dir = proj_dirs.config_dir();
        fs::create_dir_all(&config_dir).ok();
        return config_dir.to_path_buf();
    }
    PathBuf::from(CONFIG_DIR_FALLBACK)
}
