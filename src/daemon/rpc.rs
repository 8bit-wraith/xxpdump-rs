//! JSON-RPC server for LLM queries
//! Port 12346, TCP

use super::state::*;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// JSON-RPC request
#[derive(Debug, Deserialize)]
struct RpcRequest {
    method: String,
    params: Option<serde_json::Value>,
    id: Option<serde_json::Value>,
}

/// JSON-RPC response
#[derive(Debug, Serialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
    id: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

/// Summary response for LLM
#[derive(Debug, Serialize)]
pub struct SummaryResponse {
    pub devices: usize,
    pub new_devices: Vec<String>,
    pub top_talkers: Vec<TopTalker>,
    pub protocols: ProtocolDist,
    pub anomalies: Vec<String>,
    pub window: String,
}

#[derive(Debug, Serialize)]
pub struct TopTalker {
    pub ip: String,
    pub mac: String,
    pub bytes: u64,
    pub flows: usize,
}

#[derive(Debug, Serialize)]
pub struct ProtocolDist {
    pub tcp: f64,
    pub udp: f64,
    pub icmp: f64,
    pub other: f64,
}

pub type SharedState = Arc<RwLock<NetworkState>>;

/// Start JSON-RPC server
pub async fn start_rpc_server(addr: &str, state: SharedState) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("RPC server listening on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        debug!("RPC connection from {}", peer);

        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, state).await {
                error!("RPC connection error: {}", e);
            }
        });
    }
}

async fn handle_connection(stream: TcpStream, state: SharedState) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break; // Connection closed
        }

        let response = match serde_json::from_str::<RpcRequest>(&line) {
            Ok(req) => handle_request(req, &state).await,
            Err(e) => RpcResponse {
                result: None,
                error: Some(RpcError {
                    code: -32700,
                    message: format!("Parse error: {}", e),
                }),
                id: None,
            },
        };

        let mut out = serde_json::to_string(&response)?;
        out.push('\n');
        writer.write_all(out.as_bytes()).await?;
    }

    Ok(())
}

async fn handle_request(req: RpcRequest, state: &SharedState) -> RpcResponse {
    let id = req.id.clone();

    let result = match req.method.as_str() {
        "summary" => handle_summary(&req.params, state).await,
        "alerts" => handle_alerts(&req.params, state).await,
        "device.profile" => handle_device_profile(&req.params, state).await,
        "device.list" => handle_device_list(state).await,
        "watch.add" => handle_watch_add(&req.params, state).await,
        "watch.list" => handle_watch_list(state).await,
        "watch.remove" => handle_watch_remove(&req.params, state).await,
        "defense.mode" => handle_defense_mode(&req.params, state).await,
        "defense.block" => handle_defense_block(&req.params, state).await,
        "defense.unblock" => handle_defense_unblock(&req.params, state).await,
        "status" => handle_status(state).await,
        "ping" => Ok(serde_json::json!("pong")),
        "threat.add" => handle_threat_add(&req.params, state).await,
        "threat.remove" => handle_threat_remove(&req.params, state).await,
        "threat.list" => handle_threat_list(state).await,
        "threat.enable" => handle_threat_enable(&req.params, state).await,
        _ => Err(RpcError {
            code: -32601,
            message: format!("Method not found: {}", req.method),
        }),
    };

    match result {
        Ok(value) => RpcResponse {
            result: Some(value),
            error: None,
            id,
        },
        Err(err) => RpcResponse {
            result: None,
            error: Some(err),
            id,
        },
    }
}

async fn handle_summary(
    params: &Option<serde_json::Value>,
    state: &SharedState,
) -> Result<serde_json::Value, RpcError> {
    let window = params
        .as_ref()
        .and_then(|p| p.get("window"))
        .and_then(|w| w.as_str())
        .unwrap_or("5m");

    let state = state.read().await;

    let stats = match window {
        "1m" => &state.stats_1m,
        "5m" => &state.stats_5m,
        "1h" => &state.stats_1h,
        _ => &state.stats_5m,
    };

    // Find top talkers
    let mut ip_bytes: std::collections::HashMap<IpAddr, u64> = std::collections::HashMap::new();
    for (flow, fstats) in &state.flows {
        *ip_bytes.entry(flow.src_ip).or_default() += fstats.bytes;
    }

    let mut top: Vec<_> = ip_bytes.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    top.truncate(5);

    let top_talkers: Vec<TopTalker> = top
        .into_iter()
        .map(|(ip, bytes)| {
            let mac = state
                .devices
                .iter()
                .find(|(_, d)| d.ips.contains(&ip))
                .map(|(m, _)| m.to_string())
                .unwrap_or_default();

            let flows = state
                .flows
                .keys()
                .filter(|f| f.src_ip == ip)
                .count();

            TopTalker {
                ip: ip.to_string(),
                mac,
                bytes,
                flows,
            }
        })
        .collect();

    // Protocol distribution
    let total = stats.tcp_bytes + stats.udp_bytes + stats.icmp_bytes + stats.other_bytes;
    let protocols = if total > 0 {
        ProtocolDist {
            tcp: stats.tcp_bytes as f64 / total as f64,
            udp: stats.udp_bytes as f64 / total as f64,
            icmp: stats.icmp_bytes as f64 / total as f64,
            other: stats.other_bytes as f64 / total as f64,
        }
    } else {
        ProtocolDist {
            tcp: 0.0,
            udp: 0.0,
            icmp: 0.0,
            other: 0.0,
        }
    };

    // Recent new devices (last 5 minutes)
    let now = epoch_ms();
    let five_min_ago = now.saturating_sub(300_000);
    let new_devices: Vec<String> = state
        .devices
        .values()
        .filter(|d| d.first_seen > five_min_ago)
        .map(|d| d.mac.clone())
        .collect();

    // Recent anomalies
    let anomalies: Vec<String> = state
        .alerts
        .iter()
        .filter(|a| a.level <= InterestLevel::Alert && a.timestamp > five_min_ago)
        .map(|a| a.summary.clone())
        .collect();

    let summary = SummaryResponse {
        devices: state.devices.len(),
        new_devices,
        top_talkers,
        protocols,
        anomalies,
        window: window.into(),
    };

    Ok(serde_json::to_value(summary).unwrap())
}

async fn handle_alerts(
    params: &Option<serde_json::Value>,
    state: &SharedState,
) -> Result<serde_json::Value, RpcError> {
    let since = params
        .as_ref()
        .and_then(|p| p.get("since"))
        .and_then(|s| s.as_str())
        .unwrap_or("5m");

    let ms = parse_duration(since).unwrap_or(300_000);
    let cutoff = epoch_ms().saturating_sub(ms);

    let state = state.read().await;
    let alerts: Vec<_> = state
        .alerts
        .iter()
        .filter(|a| a.timestamp > cutoff)
        .cloned()
        .collect();

    Ok(serde_json::to_value(alerts).unwrap())
}

async fn handle_device_profile(
    params: &Option<serde_json::Value>,
    state: &SharedState,
) -> Result<serde_json::Value, RpcError> {
    let mac = params
        .as_ref()
        .and_then(|p| p.get("mac"))
        .and_then(|m| m.as_str())
        .ok_or_else(|| RpcError {
            code: -32602,
            message: "Missing 'mac' parameter".into(),
        })?;

    let state = state.read().await;

    // Find device by MAC string
    let device = state
        .devices
        .values()
        .find(|d| d.mac.eq_ignore_ascii_case(mac));

    match device {
        Some(d) => Ok(serde_json::to_value(d).unwrap()),
        None => Err(RpcError {
            code: -32000,
            message: format!("Device not found: {}", mac),
        }),
    }
}

async fn handle_device_list(state: &SharedState) -> Result<serde_json::Value, RpcError> {
    let state = state.read().await;
    let devices: Vec<_> = state.devices.values().cloned().collect();
    Ok(serde_json::to_value(devices).unwrap())
}

async fn handle_watch_add(
    params: &Option<serde_json::Value>,
    state: &SharedState,
) -> Result<serde_json::Value, RpcError> {
    let params = params.as_ref().ok_or_else(|| RpcError {
        code: -32602,
        message: "Missing parameters".into(),
    })?;

    let ip: Option<IpAddr> = params
        .get("ip")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok());

    let mac = params.get("mac").and_then(|v| v.as_str()).map(String::from);

    let port: Option<u16> = params.get("port").and_then(|v| v.as_u64()).map(|p| p as u16);

    let level = params
        .get("level")
        .and_then(|v| v.as_str())
        .map(|s| match s {
            "critical" => InterestLevel::Critical,
            "alert" => InterestLevel::Alert,
            "change" => InterestLevel::Change,
            "summary" => InterestLevel::Summary,
            _ => InterestLevel::Debug,
        })
        .unwrap_or(InterestLevel::Debug);

    let mut state = state.write().await;
    let id = state.add_watch(ip, mac, port, level);

    Ok(serde_json::json!({ "watch_id": id }))
}

async fn handle_watch_list(state: &SharedState) -> Result<serde_json::Value, RpcError> {
    let state = state.read().await;
    Ok(serde_json::to_value(&state.watches).unwrap())
}

async fn handle_watch_remove(
    params: &Option<serde_json::Value>,
    state: &SharedState,
) -> Result<serde_json::Value, RpcError> {
    let id = params
        .as_ref()
        .and_then(|p| p.get("id"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError {
            code: -32602,
            message: "Missing 'id' parameter".into(),
        })?;

    let mut state = state.write().await;
    let before = state.watches.len();
    state.watches.retain(|w| w.id != id);
    let removed = before != state.watches.len();

    Ok(serde_json::json!({ "removed": removed }))
}

async fn handle_defense_mode(
    params: &Option<serde_json::Value>,
    state: &SharedState,
) -> Result<serde_json::Value, RpcError> {
    let level = params
        .as_ref()
        .and_then(|p| p.get("level"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError {
            code: -32602,
            message: "Missing 'level' parameter".into(),
        })?;

    let mode = match level {
        "log" => DefenseMode::Log,
        "alert" => DefenseMode::Alert,
        "block" | "auto" => DefenseMode::AutoBlock,
        _ => {
            return Err(RpcError {
                code: -32602,
                message: format!("Invalid level: {}", level),
            })
        }
    };

    let mut state = state.write().await;
    state.defense_mode = mode;

    Ok(serde_json::json!({ "mode": level }))
}

async fn handle_defense_block(
    params: &Option<serde_json::Value>,
    state: &SharedState,
) -> Result<serde_json::Value, RpcError> {
    let params = params.as_ref().ok_or_else(|| RpcError {
        code: -32602,
        message: "Missing parameters".into(),
    })?;

    let mac = params.get("mac").and_then(|v| v.as_str()).map(String::from);
    let ip: Option<IpAddr> = params
        .get("ip")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok());

    let duration = params
        .get("duration")
        .and_then(|v| v.as_str())
        .and_then(|s| parse_duration(s));

    let reason = params
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("LLM requested block");

    let until = duration.map(|d| epoch_ms() + d).unwrap_or(0);

    let mut state = state.write().await;
    state.block_list.push(BlockEntry {
        mac,
        ip,
        reason: reason.into(),
        until,
    });

    Ok(serde_json::json!({ "blocked": true }))
}

async fn handle_defense_unblock(
    params: &Option<serde_json::Value>,
    state: &SharedState,
) -> Result<serde_json::Value, RpcError> {
    let mac = params
        .as_ref()
        .and_then(|p| p.get("mac"))
        .and_then(|v| v.as_str());

    let ip: Option<IpAddr> = params
        .as_ref()
        .and_then(|p| p.get("ip"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok());

    let mut state = state.write().await;
    let before = state.block_list.len();

    state.block_list.retain(|e| {
        let mac_match = mac.map(|m| e.mac.as_deref() != Some(m)).unwrap_or(true);
        let ip_match = ip.map(|i| e.ip != Some(i)).unwrap_or(true);
        mac_match && ip_match
    });

    let removed = before - state.block_list.len();
    Ok(serde_json::json!({ "removed": removed }))
}

async fn handle_status(state: &SharedState) -> Result<serde_json::Value, RpcError> {
    let state = state.read().await;

    Ok(serde_json::json!({
        "uptime_sec": state.started.elapsed().as_secs(),
        "devices": state.devices.len(),
        "flows": state.flows.len(),
        "alerts_queued": state.alerts.len(),
        "watches": state.watches.len(),
        "defense_mode": format!("{:?}", state.defense_mode),
        "blocked": state.block_list.len(),
    }))
}

/// Parse duration string like "5m", "1h", "30s"
fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    if s.ends_with("ms") {
        s[..s.len() - 2].parse().ok()
    } else if s.ends_with('s') {
        s[..s.len() - 1].parse::<u64>().ok().map(|v| v * 1000)
    } else if s.ends_with('m') {
        s[..s.len() - 1].parse::<u64>().ok().map(|v| v * 60_000)
    } else if s.ends_with('h') {
        s[..s.len() - 1].parse::<u64>().ok().map(|v| v * 3_600_000)
    } else {
        s.parse().ok()
    }
}

async fn handle_threat_add(
    params: &Option<serde_json::Value>,
    state: &SharedState,
) -> Result<serde_json::Value, RpcError> {
    use super::state::ThreatRule;

    let params = params.as_ref().ok_or_else(|| RpcError {
        code: -32602,
        message: "Missing parameters".into(),
    })?;

    let rule_type = params
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError {
            code: -32602,
            message: "Missing 'type' parameter".into(),
        })?;

    let rule = match rule_type {
        "block_mac" => {
            let mac = params.get("mac").and_then(|v| v.as_str()).ok_or_else(|| RpcError {
                code: -32602,
                message: "Missing 'mac' for block_mac".into(),
            })?;
            let reason = params.get("reason").and_then(|v| v.as_str()).unwrap_or("LLM rule");
            ThreatRule::BlockMac { mac: mac.into(), reason: reason.into() }
        }
        "block_ip" => {
            let ip: IpAddr = params
                .get("ip")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| RpcError {
                    code: -32602,
                    message: "Missing or invalid 'ip' for block_ip".into(),
                })?;
            let reason = params.get("reason").and_then(|v| v.as_str()).unwrap_or("LLM rule");
            ThreatRule::BlockIp { ip, reason: reason.into() }
        }
        "block_ip_range" => {
            let cidr = params.get("cidr").and_then(|v| v.as_str()).ok_or_else(|| RpcError {
                code: -32602,
                message: "Missing 'cidr' for block_ip_range".into(),
            })?;
            let reason = params.get("reason").and_then(|v| v.as_str()).unwrap_or("LLM rule");
            ThreatRule::BlockIpRange { cidr: cidr.into(), reason: reason.into() }
        }
        "arp_spoof" => ThreatRule::ArpSpoofDetect,
        "port_scan" => {
            let threshold = params.get("threshold").and_then(|v| v.as_u64()).unwrap_or(10) as u32;
            let window = params.get("window_secs").and_then(|v| v.as_u64()).unwrap_or(60) as u32;
            ThreatRule::PortScanDetect { threshold, window_secs: window }
        }
        "rate_limit" => {
            let mac = params.get("mac").and_then(|v| v.as_str()).map(String::from);
            let pps = params.get("pps_limit").and_then(|v| v.as_u64()).unwrap_or(1000) as u32;
            ThreatRule::RateLimit { mac, pps_limit: pps }
        }
        "new_device" => ThreatRule::NewDeviceAlert,
        "persistent" => {
            let mac = params.get("mac").and_then(|v| v.as_str()).ok_or_else(|| RpcError {
                code: -32602,
                message: "Missing 'mac' for persistent".into(),
            })?;
            let mins = params.get("alert_after_mins").and_then(|v| v.as_u64()).unwrap_or(30) as u32;
            ThreatRule::PersistentDevice { mac: mac.into(), alert_after_mins: mins }
        }
        _ => {
            return Err(RpcError {
                code: -32602,
                message: format!("Unknown threat type: {}", rule_type),
            });
        }
    };

    let mut state = state.write().await;
    let id = state.add_threat(rule);

    Ok(serde_json::json!({ "threat_id": id }))
}

async fn handle_threat_remove(
    params: &Option<serde_json::Value>,
    state: &SharedState,
) -> Result<serde_json::Value, RpcError> {
    let id = params
        .as_ref()
        .and_then(|p| p.get("id"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError {
            code: -32602,
            message: "Missing 'id' parameter".into(),
        })?;

    let mut state = state.write().await;
    let removed = state.remove_threat(id);

    Ok(serde_json::json!({ "removed": removed }))
}

async fn handle_threat_list(state: &SharedState) -> Result<serde_json::Value, RpcError> {
    let state = state.read().await;
    serde_json::to_value(&state.threats).map_err(|e| RpcError {
        code: -32000,
        message: format!("Serialization error: {}", e),
    })
}

async fn handle_threat_enable(
    params: &Option<serde_json::Value>,
    state: &SharedState,
) -> Result<serde_json::Value, RpcError> {
    let id = params
        .as_ref()
        .and_then(|p| p.get("id"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError {
            code: -32602,
            message: "Missing 'id' parameter".into(),
        })?;

    let enabled = params
        .as_ref()
        .and_then(|p| p.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let mut state = state.write().await;
    if let Some(entry) = state.threats.iter_mut().find(|t| t.id == id) {
        entry.enabled = enabled;
        Ok(serde_json::json!({ "id": id, "enabled": enabled }))
    } else {
        Err(RpcError {
            code: -32000,
            message: format!("Threat {} not found", id),
        })
    }
}
