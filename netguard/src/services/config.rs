use actix_web::web;

use super::start_blocknet::start_blocknet;
use super::stop_blocknet::stop_blocknet;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(start_blocknet);
    cfg.service(stop_blocknet);
}
