use crate::requests::start_blocknet::BlockNetRequest;
use anyhow::{Context, Result}; // Provides additional context on errors
use aya::maps::HashMap;
use aya::programs::xdp::{XdpLink, XdpLinkId};
use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger; // EbpfLogger for logging from aya_log crate
use clap::Parser; // Parser trait from clap for argument parsing
use core::net::Ipv4Addr;
use tracing::{info, warn}; // Use tracing for structured logging

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp58s0")]
    iface: String, // Interface name argument
}

pub async fn block_network(config_data: BlockNetRequest) -> Result<XdpLink> {
    // Parse command-line arguments
    let opt = Opt::parse();

    //Load eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/netguard"
    ))
    .context("Failed to load eBPF program")?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/netguard"
    ))
    .context("Failed to load eBPF program")?;

    // Initialize eBPF logger
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    } else {
        info!("eBPF logger initialized successfully.");
    }

    // Load and attach XDP program
    let program: &mut Xdp = bpf
        .program_mut("xdp_firewall")
        .ok_or_else(|| anyhow::anyhow!("XDP program 'xdp_firewall' not found"))?
        .try_into()?;
    program.load().context("Failed to load XDP program")?;

    let link_id: XdpLinkId = program
        .attach(&opt.iface, XdpFlags::default())
        .context("Failed to attach XDP program")?;

    let owned_link = program
        .take_link(link_id)
        .context("Failed to take ownership of XDP link")?;

    // Insert data into BLOCKED_PROTTYPE_LIST map
    let mut blocked_prottype_list: HashMap<_, u32, u32> = HashMap::try_from(
        bpf.map_mut("BLOCKED_PROTTYPE_LIST")
            .context("Failed to access BLOCKED_PROTTYPE_LIST map")?,
    )?;

    for (index, prottype) in config_data.get_blocked_protocol_type().iter().enumerate() {
        let prottype_as_u32 = match prottype.to_uppercase().as_str() {
            "TCP" => 1,
            "UDP" => 2,
            _ => {
                warn!("Unknown protocol type '{}', skipping insertion.", prottype);
                continue; // Skip unknown protocols
            }
        };
        blocked_prottype_list
            .insert(prottype_as_u32, index as u32, 0)
            .context("Failed to insert protocol type into BLOCKED_PROTTYPE_LIST map")?;
    }

    // Insert data into BLOCKED_PORT_LIST map
    let mut blocked_port_list: HashMap<_, u32, u32> = HashMap::try_from(
        bpf.map_mut("BLOCKED_PORT_LIST")
            .context("Failed to access BLOCKED_PORT_LIST map")?,
    )?;

    for (index, port) in config_data.get_blocked_ports().iter().enumerate() {
        blocked_port_list
            .insert(*port, index as u32, 0)
            .context("Failed to insert port into BLOCKED_PORT_LIST map")?;
    }

    // Insert data into BLOCKED_IP_LIST map
    let mut blocked_ip_list: HashMap<_, u32, u32> = HashMap::try_from(
        bpf.map_mut("BLOCKED_IP_LIST")
            .context("Failed to access BLOCKED_IP_LIST map")?,
    )?;

    for (index, ip_address) in config_data.get_blocked_ip_list().iter().enumerate() {
        let blocked_address: u32 = ip_address
            .parse::<Ipv4Addr>()
            .with_context(|| format!("Invalid IP address format: {}", ip_address))?
            .into();
        blocked_ip_list
            .insert(blocked_address, index as u32, 0)
            .context("Failed to insert IP address into BLOCKED_IP_LIST map")?;
    }

    // Insert data into BLOCKED_NET_TYPE_LIST map
    let mut blocked_net_type_list: HashMap<_, u32, u32> = HashMap::try_from(
        bpf.map_mut("BLOCKED_NET_TYPE_LIST")
            .context("Failed to access BLOCKED_NET_TYPE_LIST map")?,
    )?;

    for (index, nettype) in config_data.get_blocked_net_type().iter().enumerate() {
        let net_type_as_u32 = match nettype.to_uppercase().as_str() {
            "IPV4" => 1,
            "IPV6" => 2,
            _ => {
                warn!("Unknown network type '{}', skipping insertion.", nettype);
                continue; // Skip unknown network types
            }
        };
        blocked_net_type_list
            .insert(net_type_as_u32, index as u32, 0)
            .context("Failed to insert network type into BLOCKED_NET_TYPE_LIST map")?;
    }

    info!("Data insertion into eBPF maps completed successfully.");
    Ok(owned_link)
}
