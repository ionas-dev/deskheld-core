use std::{
    io::{Write, stdout},
    net::SocketAddr,
};

use anyhow::Context;
use client::Client;
use common::{
    config::CLIENT_NAME,
    connection::Connection::{Accepted, Quarantined},
};
use mdns_sd::ResolvedService;
use rustls::crypto::ring::default_provider;
use tokio::io::BufReader;
use tokio::{io::AsyncBufReadExt, select};

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
        Client::new(common_name, domain_name, client_address).expect("Failed to create client");

    println!(
        "Browsing for a host... (To select a sepcific host to connect to, enter the index of the host during browsing)"
    );
    let mut devices_receiver = client.find_server().context("Failed to find services")?;
    let mut devices: Vec<Box<ResolvedService>> = Vec::new();

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();

    let mut i = 0;
    let selected_device: Option<&Box<ResolvedService>>;
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

    let port = selected_device.get_port();

    let address = selected_device
        .get_addresses()
        .iter()
        .next()
        .map(|ip| std::net::SocketAddr::new(ip.to_ip_addr(), port))
        .context("Selected device has no address")?;

    let hostname = selected_device.get_hostname();
    let server_name = hostname.trim_end_matches('.').to_string();

    println!(
        "Connecting to {} at {}...",
        selected_device.fullname, address
    );

    let connection = client
        .connect_to(address, &server_name)
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
            std::io::stdin()
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
