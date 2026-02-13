//! Simple interactive CLI for manual Deskheld client testing.

use std::{
    io::{Write, stdout},
    net::SocketAddr,
    sync::Arc,
};

use anyhow::Context;
use client::Client;
use common::{
    config::CLIENT_NAME,
    connection::Connection::{Accepted, Quarantined},
};
use rustls::crypto::ring::default_provider;
use tokio::io::BufReader;
use tokio::{io::AsyncBufReadExt, select};

/// Starts the demo client, discovers servers, and opens an interactive connection.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    default_provider().install_default().ok();
    env_logger::init();

    let common_name = "Companion";
    let domain_name = CLIENT_NAME;
    let client_address: SocketAddr = "0.0.0.0:0".parse()?;

    println!(
        "Start client with name '{}' on domain '{}'",
        common_name, domain_name
    );

    let client =
        Client::new(common_name, domain_name, client_address).context("Failed to create client")?;

    println!(
        "Browsing for a host... (To select a sepcific host to connect to, enter the index of the host during browsing)"
    );
    let mut devices_receiver = client.find_server().context("Failed to find services")?;
    let mut devices = Vec::new();

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();

    let mut i = 0;
    let selected_device: Option<&client::Service>;
    loop {
        select! {
            Some(device) = devices_receiver.recv() => {
                i += 1;
                if i == 1 {
                    println!("Found the following :");
                }
                println!(
                    "{}. {} ({})",
                    i,
                    device.fullname,
                    device
                        .addresses
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                devices.push(device);
            }

            Ok(Some(mut line)) = reader.next_line() => {
                line = line.trim().to_string();
                if let Ok(selection) = line.trim().parse::<usize>() {
                    if selection > 0 && selection <= i {
                        selected_device = Some(&devices[selection - 1]);
                        break;
                    } else {
                        println!("Invalid index!");
                    }
                } else {
                    println!("Please enter a valid number!");
                }
            }
        }
    }

    let Some(selected_device) = selected_device else {
        println!("No device selected, exiting...");
        return Ok(());
    };

    let address = selected_device
        .first_socket_addr_v4()
        .context("Selected device has no address")?;

    let server_name = selected_device.hostname.trim_end_matches('.').to_string();

    println!(
        "Connecting to {} at {}...",
        selected_device.fullname, address
    );

    let connection = client
        .connect_to(address, server_name)
        .await
        .context("Failed to connect to server")?;

    let connection = match connection {
        Accepted(connection) => connection,
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
            std::io::stdin()
                .read_line(&mut input)
                .context("Failed to read user input")?;
            if input.trim().to_lowercase() == "y" {
                println!("Connection accepted");
                Arc::new(connection.accept().context("Failed to accept connection")?)
            } else {
                connection.reject();
                println!("Connection rejected, exiting...");
                std::process::exit(1);
            }
        }
    };

    println!(
        "Successfully connected to server with fingerprint: {}",
        connection.fingerprint()
    );

    start_simple_chat(&connection.connection).await?;

    Ok(())
}

/// Runs a minimal bidirectional chat loop over a QUIC stream.
async fn start_simple_chat(conn: &quinn::Connection) -> anyhow::Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;

    println!("--- Chat gestartet! Tippe etwas ein ---");

    let mut stdin_reader = BufReader::new(tokio::io::stdin()).lines();
    let mut buf = vec![0u8; 1024];

    loop {
        select! {
            line = stdin_reader.next_line() => {
                if let Ok(Some(text)) = line {
                    send.write_all(text.as_bytes()).await?;
                    send.write_all(b"\n").await?;
                }
            }

            res = recv.read(&mut buf) => {
                match res {
                    Ok(Some(n)) if n > 0 => {
                        let msg = String::from_utf8_lossy(&buf[..n]);
                        print!("\x1B[32mPartner:\x1B[0m {}", msg);
                    }
                    Ok(Some(_)) | Ok(None) => {
                        println!("\nVerbindung vom Partner geschlossen.");
                        break;
                    }
                    Err(e) => {
                        eprintln!("\nFehler beim Lesen: {}", e);
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}
