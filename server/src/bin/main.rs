use std::io::{self, Write, stdin, stdout};

use anyhow::Context;
use common::{
    config::{SERVER_ADDR, SERVER_NAME},
    connection::Connection::{Accepted, Quarantined},
};
use rustls::crypto::ring::default_provider;
use server::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    default_provider().install_default().ok();
    env_logger::init();

    let common_name = "Mac Server";
    let domain_name = SERVER_NAME;

    println!(
        "Start server with name '{}' on domain '{}'",
        common_name, domain_name
    );
    let (_server, mut connections) =
        Server::open(common_name, domain_name, SERVER_ADDR).context("Failed to start server")?;

    while let Some(connection) = connections.recv().await {
        match connection {
            Ok(connection) => match connection {
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
            },
            Err(e) => {
                println!("Connection error: {}", e);
            }
        }
    }

    Ok(())
}
