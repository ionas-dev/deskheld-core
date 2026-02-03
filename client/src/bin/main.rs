use std::io::{Write, stdin, stdout};

use anyhow::Context;
use client::Client;
use common::{
    config::{CLIENT_ADDR, CLIENT_NAME, SERVER_ADDR, SERVER_NAME},
    connection::Connection::{Accepted, Quarantined},
};
use rustls::crypto::ring::default_provider;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    default_provider().install_default().ok();
    env_logger::init();

    let common_name = "Companion";
    let domain_name = CLIENT_NAME;
    let client_address = CLIENT_ADDR;

    println!(
        "Start client with name '{}' on domain '{}'",
        common_name, domain_name
    );

    let client =
        Client::new(common_name, domain_name, client_address).expect("Failed to create client");
    let connection = client
        .connect_to(SERVER_ADDR, SERVER_NAME)
        .await
        .context("Failed to connect to server")?;

    match connection {
        Accepted(connection) => {
            println!(
                "Successfully connected to server with fingerprint: {}",
                connection.fingerprint()
            );
        }
        Quarantined(connection) => {
            println!(
                "Connected to server but it is quarantined with fingerprint: {}",
                connection.fingerprint()
            );

            print!(
                "Does the fingerprint match the one one the server and do you want to accept it? (y/n) ",
            );
            stdout().flush()?;
            let mut input = String::new();
            stdin()
                .read_line(&mut input)
                .context("Failed to read user input")?;
            if input.trim().to_lowercase() == "y" {
                connection.accept().context("Failed to accept connection")?;
                println!("Connection accepted");
            } else {
                connection.reject();
                println!("Connection rejected");
            }
        }
    }

    Ok(())
}
