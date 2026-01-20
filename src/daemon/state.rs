//! NetworkState - In-memory state for LLM queries
//! Compact. Efficient. Like $C000.

use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Flow identifier (5-tuple)
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8, // 6=TCP, 17=UDP, 1=ICMP
}

/// Flow statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowStats {
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: u64, // epoch ms
    pub last_seen: u64,
}

/// Device profile (what LLM sees)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub mac: String,
    pub vendor: Option<String>,
    pub ips: Vec<IpAddr>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub services: Vec<String>, // "tcp/22", "tcp/443"
    pub pattern: DevicePattern,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum DevicePattern {
    #[default]
    Unknown,
    Client,     // mostly outbound
    Server,     // mostly inbound
    Scanner,    // many ports/hosts
    Quiet,      // low traffic
}

/// Interest level for alerts
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum InterestLevel {
    Critical = 0, // deauth, ARP spoof
    Alert = 1,    // new device, port scan
    Change = 2,   // device join/leave
    Summary = 3,  // stats
    Debug = 4,    // raw packets
}

/// Alert for LLM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: u64,
    pub level: InterestLevel,
    pub category: AlertCategory,
    pub summary: String,
    pub details: serde_json::Value,
    pub timestamp: u64,
    pub source_mac: Option<String>,
    pub source_ip: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCategory {
    ArpSpoof,
    DeauthFlood,
    PortScan,
    NewDevice,
    DeviceLeft,
    UnusualProtocol,
    HighTraffic,
    WatchMatch,
    ThreatMatch,
}

/// Watch rule (LLM-defined)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchRule {
    pub id: u64,
    pub ip: Option<IpAddr>,
    pub mac: Option<String>,
    pub port: Option<u16>,
    pub level: InterestLevel,
    pub created: u64,
}

/// Threat rule types for guardian mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatRule {
    /// Block specific MAC address
    BlockMac { mac: String, reason: String },
    /// Block specific IP address
    BlockIp { ip: IpAddr, reason: String },
    /// Block IP range (CIDR notation stored as string)
    BlockIpRange { cidr: String, reason: String },
    /// Detect ARP spoofing (MAC/IP mismatch)
    ArpSpoofDetect,
    /// Detect port scanning
    PortScanDetect { threshold: u32, window_secs: u32 },
    /// Rate limit packets per second
    RateLimit { mac: Option<String>, pps_limit: u32 },
    /// Alert on new device
    NewDeviceAlert,
    /// Alert on persistent device (seen too long)
    PersistentDevice { mac: String, alert_after_mins: u32 },
}

/// Stored threat rule with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub id: u64,
    pub rule: ThreatRule,
    pub enabled: bool,
    pub hits: u64,
    pub last_hit: Option<u64>,
    pub created: u64,
}

/// Defense action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefenseMode {
    Log,       // observe only
    Alert,     // notify LLM, let it decide
    AutoBlock, // inject countermeasures
}

/// Block entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    pub mac: Option<String>,
    pub ip: Option<IpAddr>,
    pub reason: String,
    pub until: u64, // epoch ms, 0 = forever
}

/// Rolling window stats
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WindowStats {
    pub packets: u64,
    pub bytes: u64,
    pub tcp_bytes: u64,
    pub udp_bytes: u64,
    pub icmp_bytes: u64,
    pub other_bytes: u64,
    pub unique_ips: u32,
    pub unique_macs: u32,
}

/// Main state - what daemon keeps in memory
pub struct NetworkState {
    // Flow tracking
    pub flows: HashMap<FlowKey, FlowStats>,

    // Device inventory
    pub devices: HashMap<MacAddr, DeviceProfile>,

    // Rolling windows
    pub stats_1m: WindowStats,
    pub stats_5m: WindowStats,
    pub stats_1h: WindowStats,

    // Alert queue (push to LLM)
    pub alerts: VecDeque<Alert>,
    pub alert_counter: u64,

    // Watch rules (LLM-defined)
    pub watches: Vec<WatchRule>,
    pub watch_counter: u64,

    // Defense
    pub defense_mode: DefenseMode,
    pub block_list: Vec<BlockEntry>,

    // Threat rules (guardian mode)
    pub threats: Vec<ThreatEntry>,
    pub threat_counter: u64,

    // Timing
    pub started: Instant,
    pub last_1m_reset: Instant,
    pub last_5m_reset: Instant,
    pub last_1h_reset: Instant,
}

impl NetworkState {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            flows: HashMap::new(),
            devices: HashMap::new(),
            stats_1m: WindowStats::default(),
            stats_5m: WindowStats::default(),
            stats_1h: WindowStats::default(),
            alerts: VecDeque::with_capacity(100),
            alert_counter: 0,
            watches: Vec::new(),
            watch_counter: 0,
            defense_mode: DefenseMode::Log,
            block_list: Vec::new(),
            threats: Vec::new(),
            threat_counter: 0,
            started: now,
            last_1m_reset: now,
            last_5m_reset: now,
            last_1h_reset: now,
        }
    }

    /// Check and reset rolling windows
    pub fn tick_windows(&mut self) {
        let now = Instant::now();

        if now.duration_since(self.last_1m_reset) > Duration::from_secs(60) {
            self.stats_1m = WindowStats::default();
            self.last_1m_reset = now;
        }

        if now.duration_since(self.last_5m_reset) > Duration::from_secs(300) {
            self.stats_5m = WindowStats::default();
            self.last_5m_reset = now;
        }

        if now.duration_since(self.last_1h_reset) > Duration::from_secs(3600) {
            self.stats_1h = WindowStats::default();
            self.last_1h_reset = now;
        }
    }

    /// Add alert to queue
    pub fn push_alert(&mut self, level: InterestLevel, category: AlertCategory, summary: String, details: serde_json::Value) -> u64 {
        self.alert_counter += 1;
        let alert = Alert {
            id: self.alert_counter,
            level,
            category,
            summary,
            details,
            timestamp: epoch_ms(),
            source_mac: None,
            source_ip: None,
        };

        // Keep max 100 alerts
        if self.alerts.len() >= 100 {
            self.alerts.pop_front();
        }
        self.alerts.push_back(alert);
        self.alert_counter
    }

    /// Add watch rule
    pub fn add_watch(&mut self, ip: Option<IpAddr>, mac: Option<String>, port: Option<u16>, level: InterestLevel) -> u64 {
        self.watch_counter += 1;
        self.watches.push(WatchRule {
            id: self.watch_counter,
            ip,
            mac,
            port,
            level,
            created: epoch_ms(),
        });
        self.watch_counter
    }

    /// Check if IP/MAC is blocked
    pub fn is_blocked(&self, ip: Option<IpAddr>, mac: Option<&str>) -> bool {
        let now = epoch_ms();
        for entry in &self.block_list {
            // Check expiry
            if entry.until > 0 && entry.until < now {
                continue;
            }
            // Check match
            if let Some(block_ip) = entry.ip {
                if Some(block_ip) == ip {
                    return true;
                }
            }
            if let Some(ref block_mac) = entry.mac {
                if Some(block_mac.as_str()) == mac {
                    return true;
                }
            }
        }
        false
    }

    /// Add a threat rule
    pub fn add_threat(&mut self, rule: ThreatRule) -> u64 {
        self.threat_counter += 1;
        self.threats.push(ThreatEntry {
            id: self.threat_counter,
            rule,
            enabled: true,
            hits: 0,
            last_hit: None,
            created: epoch_ms(),
        });
        self.threat_counter
    }

    /// Remove a threat rule by ID
    pub fn remove_threat(&mut self, id: u64) -> bool {
        let len_before = self.threats.len();
        self.threats.retain(|t| t.id != id);
        self.threats.len() != len_before
    }

    /// Record a threat hit
    pub fn record_threat_hit(&mut self, id: u64) {
        if let Some(entry) = self.threats.iter_mut().find(|t| t.id == id) {
            entry.hits += 1;
            entry.last_hit = Some(epoch_ms());
        }
    }
}

impl Default for NetworkState {
    fn default() -> Self {
        Self::new()
    }
}

/// Current epoch in milliseconds
pub fn epoch_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
