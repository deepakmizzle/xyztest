use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockNetRequest {
    pub blocked_protocol_type: Vec<String>,
    pub blocked_ip_list: Vec<String>,
    pub blocked_ports: Vec<u32>,
    pub blocked_net_type: Vec<String>,
}

impl BlockNetRequest {
    // Getter for blocked_protocol_type
    pub fn get_blocked_protocol_type(&self) -> &Vec<String> {
        &self.blocked_protocol_type
    }
    // Getter for blocked_ip_list
    pub fn get_blocked_ip_list(&self) -> &Vec<String> {
        &self.blocked_ip_list
    }
    // Getter for blocked_ports
    pub fn get_blocked_ports(&self) -> &Vec<u32> {
        &self.blocked_ports
    }
    // Getter for blocked_net_type
    pub fn get_blocked_net_type(&self) -> &Vec<String> {
        &self.blocked_net_type
    }
    pub fn _default() -> Self {
        BlockNetRequest {
            blocked_protocol_type: Vec::new(),
            blocked_ip_list: Vec::new(),
            blocked_ports: Vec::new(),
            blocked_net_type: Vec::new(),
        }
    }
}
