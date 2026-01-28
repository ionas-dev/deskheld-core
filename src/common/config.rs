use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const QUALIFIER: &str = "com";
pub const ORGANIZATION: &str = "deskheld";
pub const APPLICATION: &str = "deskheld";

pub const SERVER_NAME: &str = "localhost";
pub const CLIENT_NAME: &str = "localhost";
pub const LOCALHOST_V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
pub const CLIENT_ADDR: SocketAddr = SocketAddr::new(LOCALHOST_V4, 5000);
pub const SERVER_ADDR: SocketAddr = SocketAddr::new(LOCALHOST_V4, 5001);
