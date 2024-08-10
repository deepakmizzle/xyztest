use crate::responses::start_blocknet::StartBlockNetResponse;
use crate::NOTIFY;
use actix_web::{get, HttpResponse, Responder};
use tracing::info; // Use tracing for structured logging

#[get("/stop_blocknet")]
async fn stop_blocknet() -> impl Responder {
    // Log the incoming request
    info!("Received request to stop blocknet");

    // Notify all waiting tasks
    NOTIFY.notify_one();
    info!("Notification sent to stop blocknet service");

    // Return a response indicating the action was taken
    HttpResponse::Ok().json(StartBlockNetResponse {
        status: "stopped".to_string(),
        message: "The blocknet service stop request has been processed.".to_string(),
    })
}
