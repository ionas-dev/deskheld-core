use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use directories::ProjectDirs;

pub const QUALIFIER: &str = "com";
pub const ORGANIZATION: &str = "deskheld";
pub const APPLICATION: &str = "deskheld";

pub const SERVER_NAME: &str = "localhost";
pub const CLIENT_NAME: &str = "localhost";
pub const LOCALHOST_V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
pub const CLIENT_ADDR: SocketAddr = SocketAddr::new(LOCALHOST_V4, 5000);
pub const SERVER_ADDR: SocketAddr = SocketAddr::new(LOCALHOST_V4, 5001);

pub const ALPN_PROTOCOLS: &[&[u8]] = &[b"deskheld-sync"];

const CONFIG_DIR_FALLBACK: &str = ".";

pub fn get_config_dir() -> PathBuf {
    if let Some(proj_dirs) = ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION) {
        let config_dir = proj_dirs.config_dir();
        fs::create_dir_all(&config_dir).ok();
        return config_dir.to_path_buf();
    }
    PathBuf::from(CONFIG_DIR_FALLBACK)
}
