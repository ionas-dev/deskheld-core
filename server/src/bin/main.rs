use std::{
    io::{Write, stdin, stdout},
    net::SocketAddr,
    sync::Arc,
};

use anyhow::Context;
use common::connection::Connection::{Accepted, Quarantined};
use rustls::crypto::ring::default_provider;
use server::Server;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    select,
};

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
        Server::create_and_open(instance_name, host_name, server_address)
            .context("Failed to start server")?;

    while let Some(connection) = connections.recv().await {
        let connection = connection.context("Failed to receive connection")?;
        let connection = match connection {
            Accepted(connection) => connection,
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
            "New accepted connection with fingerprint: {}",
            connection.fingerprint()
        );

        start_simple_chat(&connection.connection).await?;
    }

    Ok(())
}

async fn start_simple_chat(conn: &quinn::Connection) -> anyhow::Result<()> {
    let (mut send, mut recv) = conn.accept_bi().await?;

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
