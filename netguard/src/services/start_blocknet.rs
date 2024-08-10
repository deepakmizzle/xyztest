use crate::requests::start_blocknet::BlockNetRequest;
use crate::responses::start_blocknet::StartBlockNetResponse;
use crate::services_helper::blocknet::block_network;
use crate::NOTIFY;
use actix_web::{post, web, HttpResponse, Responder};
use aya::programs::Link;
use std::sync::Arc;
use tracing::{error, info}; // Using tracing for structured logging

#[post("/start_blocknet")]
async fn start_blocknet(param_obj: web::Json<BlockNetRequest>) -> impl Responder {
    // Log the incoming request
    info!(
        "Received request to start blocknet with parameters: {:?}",
        param_obj
    );

    // Call the block_network function and handle the result
    let result = block_network(param_obj.into_inner()).await;
    let link = match result {
        Ok(val) => val,
        Err(err) => {
            // Log the error and return a failure response
            error!("Failed to get the link of eBPF attached program: {}", err);
            return HttpResponse::InternalServerError().json(StartBlockNetResponse {
                status: "error".to_string(),
                message: "Failed to start the blocknet service".to_string(),
            });
        }
    };

    // Clone the Arc pointer to share the Notify instance
    let notify = Arc::clone(&*NOTIFY);

    // Spawn a new asynchronous task
    tokio::spawn(async move {
        // Wait for the notification
        notify.notified().await;

        // Attempt to detach the link and handle the result
        match link.detach() {
            Ok(val) => {
                info!("Successfully detached the link with value: {:?}", val);
            }
            Err(err) => {
                // Log the error
                error!("Failed to detach the link: {}", err);
            }
        }
    });

    // Return a success response
    HttpResponse::Ok().json(StartBlockNetResponse {
        status: "started".to_string(),
        message: "The blocknet service has been started successfully".to_string(),
    })
}
