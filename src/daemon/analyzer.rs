//! Packet analyzer - raw bytes → state updates
//! Detects anomalies, updates flows/devices

use super::enrich;
use super::state::*;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::arp::{ArpPacket, ArpOperations};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::IpAddr;

/// ARP cache for spoof detection
pub struct ArpCache {
    /// IP → (MAC, last_seen_ms)
    entries: HashMap<IpAddr, (MacAddr, u64)>,
}

impl ArpCache {
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    /// Update cache, returns Some(old_mac) if IP was seen with different MAC (potential spoof)
    pub fn update(&mut self, ip: IpAddr, mac: MacAddr) -> Option<MacAddr> {
        let now = epoch_ms();
        if let Some((old_mac, _)) = self.entries.get(&ip) {
            if *old_mac != mac {
                let old = *old_mac;
                self.entries.insert(ip, (mac, now));
                return Some(old);
            }
        }
        self.entries.insert(ip, (mac, now));
        None
    }
}

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Port scan detector
pub struct ScanDetector {
    /// src_ip → (set of dst_ports, last_reset)
    trackers: HashMap<IpAddr, (Vec<u16>, u64)>,
    threshold: usize,
    window_ms: u64,
}

impl ScanDetector {
    pub fn new(threshold: usize, window_ms: u64) -> Self {
        Self {
            trackers: HashMap::new(),
            threshold,
            window_ms,
        }
    }

    /// Track port access, returns true if scan detected
    pub fn track(&mut self, src_ip: IpAddr, dst_port: u16) -> bool {
        let now = epoch_ms();

        let (ports, last_reset) = self.trackers.entry(src_ip).or_insert((Vec::new(), now));

        // Reset window if expired
        if now - *last_reset > self.window_ms {
            ports.clear();
            *last_reset = now;
        }

        // Add port if not seen
        if !ports.contains(&dst_port) {
            ports.push(dst_port);
        }

        ports.len() >= self.threshold
    }
}

impl Default for ScanDetector {
    fn default() -> Self {
        Self::new(20, 10_000) // 20 ports in 10 seconds
    }
}

/// Analyze a raw ethernet frame, update state
pub fn analyze_packet(
    raw: &[u8],
    state: &mut NetworkState,
    arp_cache: &mut ArpCache,
    scan_detector: &mut ScanDetector,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    let now = epoch_ms();

    // Reset windows if needed
    state.tick_windows();

    // Parse ethernet
    let Some(eth) = EthernetPacket::new(raw) else {
        return alerts;
    };

    let src_mac = eth.get_source();
    let dst_mac = eth.get_destination();

    // Check against threat rules
    let src_mac_str = src_mac.to_string();
    let triggered_threats = check_threats(&src_mac_str, None, None, state);
    for (threat_id, reason) in triggered_threats {
        let alert = Alert {
            id: 0, // Will be assigned by caller or state
            level: InterestLevel::Critical,
            category: AlertCategory::ThreatMatch,
            summary: reason,
            details: serde_json::json!({
                "threat_id": threat_id,
                "src_mac": src_mac_str,
            }),
            timestamp: now,
            source_mac: Some(src_mac_str.clone()),
            source_ip: None,
        };
        alerts.push(alert);
        state.record_threat_hit(threat_id);
    }

    // Update device seen (source)
    update_device(state, src_mac, now);

    match eth.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(arp) = ArpPacket::new(eth.payload()) {
                alerts.extend(analyze_arp(&arp, state, arp_cache, now));
            }
        }
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                alerts.extend(analyze_ipv4(&ipv4, state, scan_detector, src_mac, now));
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                alerts.extend(analyze_ipv6(&ipv6, state, scan_detector, src_mac, now));
            }
        }
        _ => {
            // Other protocol
            state.stats_1m.other_bytes += raw.len() as u64;
            state.stats_5m.other_bytes += raw.len() as u64;
            state.stats_1h.other_bytes += raw.len() as u64;
        }
    }

    // Update total stats
    let len = raw.len() as u64;
    state.stats_1m.packets += 1;
    state.stats_1m.bytes += len;
    state.stats_5m.packets += 1;
    state.stats_5m.bytes += len;
    state.stats_1h.packets += 1;
    state.stats_1h.bytes += len;

    alerts
}

fn analyze_arp(
    arp: &ArpPacket,
    state: &mut NetworkState,
    arp_cache: &mut ArpCache,
    now: u64,
) -> Vec<Alert> {
    let mut alerts = Vec::new();

    // Only care about ARP replies (potential spoofing)
    if arp.get_operation() == ArpOperations::Reply {
        let sender_ip = IpAddr::V4(arp.get_sender_proto_addr());
        let sender_mac = arp.get_sender_hw_addr();

        // Check for ARP spoof
        if let Some(old_mac) = arp_cache.update(sender_ip, sender_mac) {
            let alert = Alert {
                id: 0, // Will be assigned by state.push_alert
                level: InterestLevel::Critical,
                category: AlertCategory::ArpSpoof,
                summary: format!(
                    "ARP spoof detected: {} changed from {} to {}",
                    sender_ip, old_mac, sender_mac
                ),
                details: serde_json::json!({
                    "ip": sender_ip.to_string(),
                    "old_mac": old_mac.to_string(),
                    "new_mac": sender_mac.to_string(),
                }),
                timestamp: now,
                source_mac: Some(sender_mac.to_string()),
                source_ip: Some(sender_ip),
            };
            alerts.push(alert);
        }
    }

    alerts
}

fn analyze_ipv4(
    ipv4: &Ipv4Packet,
    state: &mut NetworkState,
    scan_detector: &mut ScanDetector,
    src_mac: MacAddr,
    now: u64,
) -> Vec<Alert> {
    let mut alerts = Vec::new();

    let src_ip = IpAddr::V4(ipv4.get_source());
    let dst_ip = IpAddr::V4(ipv4.get_destination());
    let len = ipv4.get_total_length() as u64;

    // Update device IP association
    if let Some(device) = state.devices.get_mut(&src_mac) {
        if !device.ips.contains(&src_ip) {
            device.ips.push(src_ip);
        }
        device.bytes_sent += len;
        device.last_seen = now;
    }

    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            state.stats_1m.tcp_bytes += len;
            state.stats_5m.tcp_bytes += len;
            state.stats_1h.tcp_bytes += len;

            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                let flow = FlowKey {
                    src_ip,
                    dst_ip,
                    src_port: tcp.get_source(),
                    dst_port: tcp.get_destination(),
                    proto: 6,
                };
                update_flow(state, flow, len, now);

                // Port scan detection
                if scan_detector.track(src_ip, tcp.get_destination()) {
                    let alert = Alert {
                        id: 0,
                        level: InterestLevel::Alert,
                        category: AlertCategory::PortScan,
                        summary: format!("Port scan detected from {}", src_ip),
                        details: serde_json::json!({
                            "src_ip": src_ip.to_string(),
                            "src_mac": src_mac.to_string(),
                        }),
                        timestamp: now,
                        source_mac: Some(src_mac.to_string()),
                        source_ip: Some(src_ip),
                    };
                    alerts.push(alert);
                }

                // Track services
                let port = tcp.get_destination();
                if is_server_port(port) {
                    let service = format!("tcp/{}", port);
                    // Would add to dst device, but we don't have dst_mac here
                }
            }
        }
        IpNextHeaderProtocols::Udp => {
            state.stats_1m.udp_bytes += len;
            state.stats_5m.udp_bytes += len;
            state.stats_1h.udp_bytes += len;

            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                let flow = FlowKey {
                    src_ip,
                    dst_ip,
                    src_port: udp.get_source(),
                    dst_port: udp.get_destination(),
                    proto: 17,
                };
                update_flow(state, flow, len, now);
            }
        }
        IpNextHeaderProtocols::Icmp => {
            state.stats_1m.icmp_bytes += len;
            state.stats_5m.icmp_bytes += len;
            state.stats_1h.icmp_bytes += len;
        }
        _ => {
            state.stats_1m.other_bytes += len;
            state.stats_5m.other_bytes += len;
            state.stats_1h.other_bytes += len;
        }
    }

    alerts
}

fn analyze_ipv6(
    ipv6: &Ipv6Packet,
    state: &mut NetworkState,
    scan_detector: &mut ScanDetector,
    src_mac: MacAddr,
    now: u64,
) -> Vec<Alert> {
    let alerts = Vec::new();

    let src_ip = IpAddr::V6(ipv6.get_source());
    let dst_ip = IpAddr::V6(ipv6.get_destination());
    let len = ipv6.get_payload_length() as u64 + 40; // + header

    // Update device IP association
    if let Some(device) = state.devices.get_mut(&src_mac) {
        if !device.ips.contains(&src_ip) {
            device.ips.push(src_ip);
        }
        device.bytes_sent += len;
        device.last_seen = now;
    }

    match ipv6.get_next_header() {
        IpNextHeaderProtocols::Tcp => {
            state.stats_1m.tcp_bytes += len;
            state.stats_5m.tcp_bytes += len;
            state.stats_1h.tcp_bytes += len;

            if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                let flow = FlowKey {
                    src_ip,
                    dst_ip,
                    src_port: tcp.get_source(),
                    dst_port: tcp.get_destination(),
                    proto: 6,
                };
                update_flow(state, flow, len, now);
            }
        }
        IpNextHeaderProtocols::Udp => {
            state.stats_1m.udp_bytes += len;
            state.stats_5m.udp_bytes += len;
            state.stats_1h.udp_bytes += len;

            if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                let flow = FlowKey {
                    src_ip,
                    dst_ip,
                    src_port: udp.get_source(),
                    dst_port: udp.get_destination(),
                    proto: 17,
                };
                update_flow(state, flow, len, now);
            }
        }
        IpNextHeaderProtocols::Icmpv6 => {
            state.stats_1m.icmp_bytes += len;
            state.stats_5m.icmp_bytes += len;
            state.stats_1h.icmp_bytes += len;
        }
        _ => {
            state.stats_1m.other_bytes += len;
            state.stats_5m.other_bytes += len;
            state.stats_1h.other_bytes += len;
        }
    }

    alerts
}

fn update_device(state: &mut NetworkState, mac: MacAddr, now: u64) {
    if !state.devices.contains_key(&mac) {
        // New device!
        let profile = DeviceProfile {
            mac: mac.to_string(),
            vendor: enrich::lookup_vendor(&mac),
            ips: Vec::new(),
            first_seen: now,
            last_seen: now,
            bytes_sent: 0,
            bytes_recv: 0,
            services: Vec::new(),
            pattern: DevicePattern::Unknown,
        };
        state.devices.insert(mac, profile);

        // Generate alert for new device
        state.push_alert(
            InterestLevel::Alert,
            AlertCategory::NewDevice,
            format!("New device: {}", mac),
            serde_json::json!({ "mac": mac.to_string() }),
        );
    } else {
        state.devices.get_mut(&mac).unwrap().last_seen = now;
    }
}

fn update_flow(state: &mut NetworkState, key: FlowKey, bytes: u64, now: u64) {
    let entry = state.flows.entry(key).or_insert(FlowStats {
        packets: 0,
        bytes: 0,
        first_seen: now,
        last_seen: now,
    });
    entry.packets += 1;
    entry.bytes += bytes;
    entry.last_seen = now;
}

/// Check if port is typically a server port
fn is_server_port(port: u16) -> bool {
    matches!(port, 22 | 80 | 443 | 8080 | 3306 | 5432 | 6379 | 27017)
}

/// Check packet against threat rules, return any triggered threats
pub fn check_threats(
    src_mac: &str,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    state: &NetworkState,
) -> Vec<(u64, String)> {
    use super::state::ThreatRule;

    let mut triggered = Vec::new();

    for entry in &state.threats {
        if !entry.enabled {
            continue;
        }

        let matched = match &entry.rule {
            ThreatRule::BlockMac { mac, reason } => {
                if mac.eq_ignore_ascii_case(src_mac) {
                    Some(format!("Blocked MAC {} seen: {}", mac, reason))
                } else {
                    None
                }
            }
            ThreatRule::BlockIp { ip, reason } => {
                if src_ip == Some(*ip) || dst_ip == Some(*ip) {
                    Some(format!("Blocked IP {} seen: {}", ip, reason))
                } else {
                    None
                }
            }
            ThreatRule::BlockIpRange { cidr, reason } => {
                // Simple prefix check for now (proper CIDR parsing can be added later)
                let prefix = cidr.split('/').next().unwrap_or("");
                let matches = src_ip
                    .map(|ip| ip.to_string().starts_with(prefix))
                    .unwrap_or(false)
                    || dst_ip
                        .map(|ip| ip.to_string().starts_with(prefix))
                        .unwrap_or(false);
                if matches {
                    Some(format!("Blocked IP range {} seen: {}", cidr, reason))
                } else {
                    None
                }
            }
            // ArpSpoofDetect is handled separately in analyze_arp
            ThreatRule::ArpSpoofDetect => None,
            // PortScanDetect is handled separately in ScanDetector
            ThreatRule::PortScanDetect { .. } => None,
            // RateLimit requires packet counting (future enhancement)
            ThreatRule::RateLimit { .. } => None,
            // NewDeviceAlert is handled in device tracking
            ThreatRule::NewDeviceAlert => None,
            // PersistentDevice requires time tracking (future enhancement)
            ThreatRule::PersistentDevice { .. } => None,
        };

        if let Some(reason) = matched {
            triggered.push((entry.id, reason));
        }
    }

    triggered
}

