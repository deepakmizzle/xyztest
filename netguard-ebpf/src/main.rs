#![no_std]
#![no_main]

use aya_ebpf::maps::HashMap;
use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    programs::XdpContext,
};
use aya_log_ebpf::info;
// mod config;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
static BLOCKED_PROTTYPE_LIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map]
static BLOCKED_PORT_LIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map]
static BLOCKED_IP_LIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map]
static BLOCKED_NET_TYPE_LIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    let ret = match try_xdp_firewall(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    };
    // info!(&ctx,"{}",ret);
    ret
}

#[inline(always)] // (1)
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    // info!(ctx,"start: {},end:{}",start,end);

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; // (2)
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            if unsafe { BLOCKED_NET_TYPE_LIST.get(&1) }.is_some() {
                info!(ctx, "Rejecting the IPV4 net type");
                return Err(());
            } else {
                {}
            }
        }
        EtherType::Ipv6 => {
            if unsafe { BLOCKED_NET_TYPE_LIST.get(&2) }.is_some() {
                info!(ctx, "Rejecting the IPV6 net type");
                return Err(());
            } else {
                {}
            }
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    //Checking IP address Acceptance
    if unsafe { BLOCKED_IP_LIST.get(&source_addr) }.is_some() {
        info!(ctx, "Rejecting the SRC IP: {:i}", source_addr);
        return Err(());
    }

    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            if unsafe { BLOCKED_PROTTYPE_LIST.get(&1) }.is_some() {
                info!(ctx, "Rejecting the TCP SRC IP: {:i}", source_addr);
                return Err(());
            } else {
                let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                u16::from_be(unsafe { (*tcphdr).source })
            }
        }
        IpProto::Udp => {
            if unsafe { BLOCKED_PROTTYPE_LIST.get(&2) }.is_some() {
                info!(ctx, "Rejecting the UDP SRC IP: {:i}", source_addr);
                return Err(());
            } else {
                let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                u16::from_be(unsafe { (*udphdr).source })
            }
        }
        _ => return Err(()),
    };
    //checking the Port Acceptance
    if unsafe { BLOCKED_PORT_LIST.get(&(source_port as u32)) }.is_some() {
        info!(
            ctx,
            "Rejecting SRC IP: {:i}, SRC PORT: {}", source_addr, source_port
        );
        return Err(());
    } else {
        info!(
            ctx,
            "accepting the SRC IP: {:i}, SRC PORT: {}", source_addr, source_port
        );
        Ok(xdp_action::XDP_PASS)
    }
}
