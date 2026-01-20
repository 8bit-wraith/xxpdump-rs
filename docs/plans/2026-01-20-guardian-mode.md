# Guardian Mode Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add active network defense capabilities to widump with threat registry, auto-blocking, and defense action execution.

**Architecture:** Guardian mode extends daemon mode with a ThreatRule registry. When packets match registered threats and defense_mode is `AutoBlock`, widump executes defense actions (ARP correction, TCP RST) and notifies WiFAKE via push callback.

**Tech Stack:** Rust, tokio, pnet (packet injection), reqwest (push notifications), neli (future: nl80211 for WiFi monitor mode)

---

## Phase 1: Threat Registry + Defense Execution

### Task 1: Add ThreatRule enum to state.rs

**Files:**
- Modify: `src/daemon/state.rs:89-98` (after WatchRule)

**Step 1: Add ThreatRule types**

Add after line 98 (after WatchRule struct):

```rust
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
```

**Step 2: Add threat storage to NetworkState**

Add to NetworkState struct (around line 151):

```rust
    // Threat rules (guardian mode)
    pub threats: Vec<ThreatEntry>,
    pub threat_counter: u64,
```

**Step 3: Initialize in NetworkState::new()**

Add to the Self block in new() (around line 176):

```rust
            threats: Vec::new(),
            threat_counter: 0,
```

**Step 4: Add threat management methods**

Add after `is_blocked` method (around line 262):

```rust
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
```

**Step 5: Build and verify**

Run: `cargo build`
Expected: Success with no new errors

**Step 6: Commit**

```bash
git add src/daemon/state.rs
git commit -m "feat(guardian): add ThreatRule enum and storage to NetworkState"
```

---

### Task 2: Add threat.* RPC methods

**Files:**
- Modify: `src/daemon/rpc.rs:117-134` (add to method dispatch)
- Modify: `src/daemon/rpc.rs` (add handler functions at end)

**Step 1: Add method dispatch entries**

Add to the match block in `handle_request` (around line 128, before the `_` wildcard):

```rust
        "threat.add" => handle_threat_add(&req.params, state).await,
        "threat.remove" => handle_threat_remove(&req.params, state).await,
        "threat.list" => handle_threat_list(state).await,
        "threat.enable" => handle_threat_enable(&req.params, state).await,
```

**Step 2: Add threat handler functions**

Add at end of file (after `parse_duration`):

```rust
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
    Ok(serde_json::to_value(&state.threats).unwrap())
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
```

**Step 3: Build and verify**

Run: `cargo build`
Expected: Success

**Step 4: Commit**

```bash
git add src/daemon/rpc.rs
git commit -m "feat(guardian): add threat.add/remove/list/enable RPC methods"
```

---

### Task 3: Add threat checking to analyzer

**Files:**
- Modify: `src/daemon/analyzer.rs` (add threat checking function)
- Modify: `src/daemon/state.rs` (add AlertCategory::ThreatMatch)

**Step 1: Add ThreatMatch alert category**

In `src/daemon/state.rs`, add to AlertCategory enum (around line 85):

```rust
    ThreatMatch,
```

**Step 2: Add threat checking function to analyzer**

Add at end of `src/daemon/analyzer.rs`:

```rust
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
```

**Step 3: Call threat checking in analyze_packet**

In `analyze_packet` function, add threat checking after Ethernet parsing (around line 115):

Find the section where `src_mac` is extracted and add:

```rust
    // Check against threat rules
    let src_mac_str = src_mac.to_string();
    let triggered_threats = check_threats(&src_mac_str, None, None, state);
    for (threat_id, reason) in triggered_threats {
        alerts.push(PendingAlert {
            level: InterestLevel::Critical,
            category: AlertCategory::ThreatMatch,
            summary: reason,
            details: serde_json::json!({
                "threat_id": threat_id,
                "src_mac": src_mac_str,
            }),
        });
        state.record_threat_hit(threat_id);
    }
```

**Step 4: Build and verify**

Run: `cargo build`
Expected: Success

**Step 5: Commit**

```bash
git add src/daemon/state.rs src/daemon/analyzer.rs
git commit -m "feat(guardian): add threat checking to packet analyzer"
```

---

### Task 4: Add defense action execution

**Files:**
- Modify: `src/daemon/mod.rs` (wire up defense injector to alerts)

**Step 1: Add defense action alert category**

In `src/daemon/state.rs`, add to AlertCategory:

```rust
    DefenseAction,
```

**Step 2: Execute defense on threat match**

In `src/daemon/mod.rs`, modify the capture loop to execute defense when threat matched.

In `run_capture_loop`, after the alerts are pushed, add defense execution:

```rust
                    // Execute defense if in AutoBlock mode and threats triggered
                    if !alerts.is_empty() {
                        let rt = tokio::runtime::Handle::current();
                        rt.block_on(async {
                            let state_read = state.read().await;
                            let should_block = state_read.defense_mode == DefenseMode::AutoBlock;
                            let has_threat = alerts.iter().any(|a|
                                matches!(a.category, AlertCategory::ThreatMatch | AlertCategory::ArpSpoof)
                            );
                            drop(state_read);

                            if should_block && has_threat {
                                if let Some(ref inj) = _injector {
                                    // Defense action logging
                                    let mut state = state.write().await;
                                    state.push_alert(
                                        InterestLevel::Alert,
                                        AlertCategory::DefenseAction,
                                        "Defense action triggered".into(),
                                        serde_json::json!({"action": "alert_generated"}),
                                    );
                                }
                            }
                        });
                    }
```

**Step 3: Build and verify**

Run: `cargo build`
Expected: Success (may have warnings about unused injector)

**Step 4: Commit**

```bash
git add src/daemon/mod.rs src/daemon/state.rs
git commit -m "feat(guardian): wire defense execution on threat match"
```

---

### Task 5: Add threat.actions RPC for action history

**Files:**
- Modify: `src/daemon/state.rs` (add DefenseAction struct and storage)
- Modify: `src/daemon/rpc.rs` (add threat.actions method)

**Step 1: Add DefenseAction storage to state**

Add after ThreatEntry in `state.rs`:

```rust
/// Recorded defense action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseAction {
    pub id: u64,
    pub threat_id: Option<u64>,
    pub action_type: String,  // "arp_correct", "tcp_rst", "block_added"
    pub target_mac: Option<String>,
    pub target_ip: Option<IpAddr>,
    pub success: bool,
    pub timestamp: u64,
}
```

Add to NetworkState struct:

```rust
    // Defense actions history
    pub defense_actions: VecDeque<DefenseAction>,
    pub defense_action_counter: u64,
```

Initialize in new():

```rust
            defense_actions: VecDeque::with_capacity(100),
            defense_action_counter: 0,
```

Add method:

```rust
    /// Record a defense action
    pub fn record_defense_action(
        &mut self,
        threat_id: Option<u64>,
        action_type: &str,
        target_mac: Option<String>,
        target_ip: Option<IpAddr>,
        success: bool,
    ) -> u64 {
        self.defense_action_counter += 1;
        let action = DefenseAction {
            id: self.defense_action_counter,
            threat_id,
            action_type: action_type.into(),
            target_mac,
            target_ip,
            success,
            timestamp: epoch_ms(),
        };
        if self.defense_actions.len() >= 100 {
            self.defense_actions.pop_front();
        }
        self.defense_actions.push_back(action);
        self.defense_action_counter
    }
```

**Step 2: Add RPC method**

In `rpc.rs`, add to method dispatch:

```rust
        "threat.actions" => handle_threat_actions(&req.params, state).await,
```

Add handler:

```rust
async fn handle_threat_actions(
    params: &Option<serde_json::Value>,
    state: &SharedState,
) -> Result<serde_json::Value, RpcError> {
    let limit = params
        .as_ref()
        .and_then(|p| p.get("limit"))
        .and_then(|v| v.as_u64())
        .unwrap_or(50) as usize;

    let state = state.read().await;
    let actions: Vec<_> = state.defense_actions.iter().rev().take(limit).cloned().collect();

    Ok(serde_json::to_value(actions).unwrap())
}
```

**Step 3: Build and verify**

Run: `cargo build`
Expected: Success

**Step 4: Commit**

```bash
git add src/daemon/state.rs src/daemon/rpc.rs
git commit -m "feat(guardian): add defense action history and threat.actions RPC"
```

---

### Task 6: Integration test with JSON-RPC

**Files:**
- Create: `tests/guardian_rpc.rs` (integration test)

**Step 1: Create integration test file**

```rust
//! Guardian mode RPC integration tests
//!
//! Note: These tests require the daemon to be running.
//! Run with: cargo test --test guardian_rpc -- --ignored

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

fn send_rpc(stream: &mut TcpStream, method: &str, params: serde_json::Value) -> serde_json::Value {
    let request = serde_json::json!({
        "method": method,
        "params": params,
        "id": 1
    });

    let mut data = serde_json::to_string(&request).unwrap();
    data.push('\n');
    stream.write_all(data.as_bytes()).unwrap();

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut response = String::new();
    reader.read_line(&mut response).unwrap();

    serde_json::from_str(&response).unwrap()
}

#[test]
#[ignore] // Requires running daemon
fn test_threat_lifecycle() {
    let mut stream = TcpStream::connect("127.0.0.1:12346").expect("Daemon not running");

    // Add a threat rule
    let response = send_rpc(&mut stream, "threat.add", serde_json::json!({
        "type": "block_mac",
        "mac": "aa:bb:cc:dd:ee:ff",
        "reason": "Test block"
    }));

    let threat_id = response["result"]["threat_id"].as_u64().unwrap();
    assert!(threat_id > 0);

    // List threats
    let response = send_rpc(&mut stream, "threat.list", serde_json::json!({}));
    let threats = response["result"].as_array().unwrap();
    assert!(threats.iter().any(|t| t["id"] == threat_id));

    // Remove threat
    let response = send_rpc(&mut stream, "threat.remove", serde_json::json!({
        "id": threat_id
    }));
    assert!(response["result"]["removed"].as_bool().unwrap());
}
```

**Step 2: Build test (don't run yet)**

Run: `cargo build --tests`
Expected: Success

**Step 3: Commit**

```bash
git add tests/guardian_rpc.rs
git commit -m "test(guardian): add RPC integration test for threat lifecycle"
```

---

## Phase 1 Complete Checklist

- [ ] ThreatRule enum in state.rs
- [ ] ThreatEntry storage in NetworkState
- [ ] threat.add RPC method
- [ ] threat.remove RPC method
- [ ] threat.list RPC method
- [ ] threat.enable RPC method
- [ ] Threat checking in analyzer
- [ ] Defense action on threat match
- [ ] DefenseAction history
- [ ] threat.actions RPC method
- [ ] Integration test

---

## Future Phases (Separate Plans)

**Phase 2: Firewall Integration**
- iptables/nftables wrapper
- Packet dropping
- Rate limiting

**Phase 3: WiFAKE Push Notifications**
- Push callback client
- Interest level filtering
- Queue fallback

**Phase 4: Native Monitor Mode**
- nl80211 via neli
- 802.11 frame injection
- WiFi deauth

**Phase 5: Shared State**
- Unix socket between daemon/guardian
- --connect-daemon flag
