use serde::{Deserialize, Serialize};
#[derive(Debug, Deserialize, Serialize)]
pub struct StartBlockNetResponse {
    pub status: String,
    pub message: String,
}
