use actix_web::{App, HttpServer};
mod requests;
mod responses;
mod services;
mod services_helper;
use dotenv::dotenv;
use once_cell::sync::Lazy;
use services::config::config;
use std::env;
use std::sync::Arc;
use tokio::sync::Notify;
use tracing::{error, info};
static NOTIFY: Lazy<Arc<Notify>> = Lazy::new(|| Arc::new(Notify::new()));
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables from a `.env` file
    dotenv().ok();

    // Retrieve and validate SERVER_IP
    let server_ip = match env::var("SERVER_IP") {
        Ok(val) => val,
        Err(e) => {
            error!("Failed to retrieve SERVER_IP environment variable: {}", e);
            panic!("SERVER_IP environment variable is required.");
        }
    };

    // Retrieve and validate PORT
    let port: u16 = match env::var("PORT") {
        Ok(val) => match val.parse::<u16>() {
            Ok(p) => p,
            Err(e) => {
                error!("Invalid port number provided: {}", e);
                panic!("PORT environment variable must be a valid u16 integer.");
            }
        },
        Err(e) => {
            error!("Failed to retrieve PORT environment variable: {}", e);
            panic!("PORT environment variable is required.");
        }
    };

    // Log server configuration
    info!(
        "Starting server at address: {} on port: {}",
        server_ip, port
    );

    // Get the number of available CPU cores
    let num_cpus = num_cpus::get();
    info!("Detected {} CPU cores.", num_cpus);

    // Set up logging
    std::env::set_var("RUST_LOG", "debug");
    tracing_subscriber::fmt::init();

    // Start the HTTP server
    HttpServer::new(move || App::new().configure(config))
        .workers(num_cpus) // Set the number of worker threads
        .bind((server_ip.as_str(), port))?
        .run()
        .await
}
