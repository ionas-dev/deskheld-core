use std::{
    io::{Write, stdin, stdout},
    net::SocketAddr,
};

use anyhow::Context;
use common::connection::Connection::{Accepted, Quarantined};
use rustls::crypto::ring::default_provider;
use server::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    default_provider().install_default().ok();
    env_logger::init();

    let instance_name = "MacBook Air M1";
    let host_name = "macbook-air-m1";
    let server_address: SocketAddr = "0.0.0.0:0".parse()?;

    println!(
        "Start server with instance name '{}' and host name '{}'",
        instance_name, host_name
    );

    let (_server, mut connections) =
        Server::open(instance_name, host_name, server_address).context("Failed to start server")?;

    while let Some(connection) = connections.recv().await {
        let connection = connection.context("Failed to receive connection")?;
        match connection {
            Quarantined(connection) => {
                println!(
                    "New quarantined connection with fingerprint: {}",
                    connection.fingerprint()
                );

                print!(
                    "Does the fingerprint match the one one the server and do you want to accept it? (y/n) ",
                );
                stdout().flush()?;
                let mut input = String::new();
                stdin().read_line(&mut input)?;
                if input.trim().to_lowercase() == "y" {
                    connection.accept().context("Failed to accept connection")?;
                    println!("Connection accepted");
                } else {
                    connection.reject();
                    println!("Connection rejected");
                }
            }
            Accepted(connection) => {
                println!(
                    "New accepted connection with fingerprint: {}",
                    connection.fingerprint()
                );
            }
        }
    }

    Ok(())
}
