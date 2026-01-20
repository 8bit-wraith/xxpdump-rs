//! Active defense - packet injection responses
//! Counter ARP spoofing, TCP RST injection, etc.

use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use tracing::{debug, warn, info};

/// Defense injector
pub struct DefenseInjector {
    interface: Option<NetworkInterface>,
    tx: Option<Box<dyn datalink::DataLinkSender>>,
}

impl DefenseInjector {
    /// Create new injector for interface
    pub fn new(interface_name: &str) -> Self {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|i| i.name == interface_name);

        match interface {
            Some(iface) => {
                match datalink::channel(&iface, Default::default()) {
                    Ok(Channel::Ethernet(tx, _rx)) => {
                        info!("Defense injector ready on {}", interface_name);
                        Self {
                            interface: Some(iface),
                            tx: Some(tx),
                        }
                    }
                    Ok(_) => {
                        warn!("Non-ethernet channel on {}", interface_name);
                        Self { interface: None, tx: None }
                    }
                    Err(e) => {
                        warn!("Failed to create channel on {}: {}", interface_name, e);
                        Self { interface: None, tx: None }
                    }
                }
            }
            None => {
                warn!("Interface {} not found", interface_name);
                Self { interface: None, tx: None }
            }
        }
    }

    /// Check if injector is ready
    pub fn is_ready(&self) -> bool {
        self.tx.is_some()
    }

    /// Send gratuitous ARP to correct ARP cache poisoning
    /// Tells everyone: "This IP belongs to this MAC"
    pub fn send_arp_correction(&mut self, ip: Ipv4Addr, correct_mac: MacAddr) -> bool {
        let Some(ref iface) = self.interface else {
            return false;
        };
        let Some(ref mut tx) = self.tx else {
            return false;
        };

        let src_mac = iface.mac.unwrap_or(MacAddr::zero());

        // Build gratuitous ARP reply
        let mut eth_buf = [0u8; 42]; // 14 eth + 28 arp
        let mut eth = MutableEthernetPacket::new(&mut eth_buf).unwrap();

        eth.set_destination(MacAddr::broadcast());
        eth.set_source(correct_mac);
        eth.set_ethertype(EtherTypes::Arp);

        let mut arp_buf = [0u8; 28];
        let mut arp = MutableArpPacket::new(&mut arp_buf).unwrap();

        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Reply);
        arp.set_sender_hw_addr(correct_mac);
        arp.set_sender_proto_addr(ip);
        arp.set_target_hw_addr(MacAddr::broadcast());
        arp.set_target_proto_addr(ip);

        eth.set_payload(arp.packet());

        match tx.send_to(eth.packet(), None) {
            Some(Ok(_)) => {
                debug!("Sent ARP correction: {} is {}", ip, correct_mac);
                true
            }
            _ => {
                warn!("Failed to send ARP correction");
                false
            }
        }
    }

    /// Send TCP RST to kill a connection
    /// Used to interrupt suspicious connections
    pub fn send_tcp_rst(
        &mut self,
        src_mac: MacAddr,
        dst_mac: MacAddr,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
    ) -> bool {
        let Some(ref mut tx) = self.tx else {
            return false;
        };

        // Build RST packet
        // Ethernet (14) + IPv4 (20) + TCP (20) = 54 bytes
        let mut buf = [0u8; 54];

        // Ethernet header
        let mut eth = MutableEthernetPacket::new(&mut buf[0..14]).unwrap();
        eth.set_destination(dst_mac);
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Ipv4);

        // IPv4 header
        let mut ip = MutableIpv4Packet::new(&mut buf[14..34]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40); // 20 IP + 20 TCP
        ip.set_ttl(64);
        ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        // Note: checksum would need to be calculated

        // TCP header
        let mut tcp = MutableTcpPacket::new(&mut buf[34..54]).unwrap();
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq_num);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::RST);
        tcp.set_window(0);
        // Note: checksum would need to be calculated

        match tx.send_to(&buf, None) {
            Some(Ok(_)) => {
                debug!(
                    "Sent TCP RST: {}:{} -> {}:{}",
                    src_ip, src_port, dst_ip, dst_port
                );
                true
            }
            _ => {
                warn!("Failed to send TCP RST");
                false
            }
        }
    }

    /// Send deauth frame (requires monitor mode WiFi)
    /// This is more complex and requires radiotap header + 802.11 frames
    /// Placeholder for now
    pub fn send_wifi_deauth(&mut self, _bssid: MacAddr, _client: MacAddr) -> bool {
        // Would need a monitor mode interface and 802.11 frame construction
        // Not implemented yet - needs different interface type
        warn!("WiFi deauth not implemented - requires monitor mode");
        false
    }
}

/// Defense action result
#[derive(Debug, Clone)]
pub struct DefenseResult {
    pub action: DefenseActionType,
    pub success: bool,
    pub target_ip: Option<Ipv4Addr>,
    pub target_mac: Option<MacAddr>,
}

#[derive(Debug, Clone)]
pub enum DefenseActionType {
    ArpCorrection,
    TcpRst,
    WifiDeauth,
}
