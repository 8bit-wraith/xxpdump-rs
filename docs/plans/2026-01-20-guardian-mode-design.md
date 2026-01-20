# Guardian Mode Design

**Date:** 2026-01-20
**Status:** Draft
**Author:** Brainstorming session

## Overview

Add a new "guardian" mode to widump that provides active network defense capabilities. Guardian mode complements the existing daemon mode (read-only sensor) with packet injection, threat blocking, and real-time response to attacks.

This integrates with the WiFAKE ecosystem as an active defense layer that the LLM can command.

## WiFAKE Ecosystem Context

```
                     ┌──────────────────────────────────────┐
                     │         wifake server                │
                     │    ┌──────────────────────┐          │
                     │    │   Liquid AI (LLM)    │          │
                     │    │   "The Brain"        │          │
                     │    └──────────┬───────────┘          │
                     │               │                      │
                     │    ┌──────────▼───────────┐          │
                     │    │   Sensor Aggregator  │          │
                     │    │   + Alert Engine     │          │
                     │    └──────────┬───────────┘          │
                     └───────────────┼──────────────────────┘
                                     │
          ┌──────────────────────────┼──────────────────────────┐
          │                          │                          │
          ▼                          ▼                          ▼
┌─────────────────┐      ┌─────────────────┐        ┌─────────────────┐
│  widump daemon  │      │ widump guardian │        │  other sensors  │
│  (read-only)    │      │ (active defense)│        │  (DSPradio,     │
│                 │      │                 │        │   ESP32 mesh)   │
│ • Flow analysis │      │ • Promiscuous   │        │                 │
│ • Device profile│      │ • Monitor mode  │        │                 │
│ • Anomaly detect│      │ • Packet inject │        │                 │
└────────┬────────┘      └────────┬────────┘        └────────┬────────┘
         │                        │                          │
         └────────────────────────┼──────────────────────────┘
                                  │
                       Avahi/mDNS: _widump._tcp
```

## Architecture

### Layered Mode Structure

| Mode | Purpose | Capabilities |
|------|---------|--------------|
| `daemon` | Read-only sensor | Flow analysis, device profiling, anomaly detection |
| `guardian` | Active defense | All daemon + promiscuous, monitor mode, packet injection |

Both modes can run simultaneously on different interfaces. They share NetworkState via Unix socket or shared memory.

### Threat Detection Flow

```
Packet arrives
    │
    ▼
Analyzer checks ThreatRules
    │
    ├─ No match → normal processing
    │
    └─ Match found
           │
           ▼
    Check defense_mode
           │
           ├─ log    → log only
           ├─ alert  → log + push to WiFAKE
           └─ block  → log + push + execute defense action
                              │
                              ▼
                    DefenseAction (RST, ARP correct, drop, throttle)
                              │
                              ▼
                    Queue action result for LLM
```

### Notification Model

| Priority | Action | Delivery |
|----------|--------|----------|
| Critical | Blocked active attack | Push immediately to WiFAKE |
| Alert | Suspicious activity | Push within 5s |
| Change | Device joined/left | On request |
| Summary | Stats, top talkers | On request |
| Debug | Raw packet details | Only when LLM asks |

Push notifications require WiFAKE callback endpoint. All actions queued for LLM polling as fallback.

## Threat Registry

### Threat Rule Types

```rust
enum ThreatRule {
    // === Simple Blocklists ===
    BlockMac(MacAddr),
    BlockIp(IpAddr),
    BlockIpRange(IpNet),

    // === Pattern-Based Detection ===
    ArpSpoofDetect,                    // MAC/IP mismatch in ARP
    PortScanDetect {
        threshold: u32,                // ports touched
        window_secs: u32,              // time window
    },

    // === Behavioral Rules ===
    RateLimit {
        mac: Option<MacAddr>,          // None = any device
        pps_limit: u32,                // packets per second
    },
    ConnectionAttempts {
        target: IpAddr,
        max_attempts: u32,
        window_secs: u32,
    },

    // === Persistence-Based (WiFAKE protection vision) ===
    PersistentDevice {
        mac: MacAddr,
        alert_after_mins: u32,         // "seen too long near vulnerable person"
    },
    NewDeviceWatch,                    // any unknown MAC appears

    // === Relationship-Based ===
    DeviceCluster {
        macs: Vec<MacAddr>,            // devices normally seen together
        alert_if_partial: bool,        // alert if only some appear (split group)
    },

    // === LLM-Defined ===
    CustomPattern {
        name: String,
        filter: String,                // BPF-like expression
        action: DefenseAction,
    },
}
```

### JSON-RPC API Extensions

| Method | Purpose |
|--------|---------|
| `threat.add` | Register new threat rule |
| `threat.remove` | Remove rule by ID |
| `threat.list` | List active rules |
| `threat.actions` | Recent defensive actions taken |
| `defense.push_endpoint` | Set WiFAKE callback URL |

## Defense Actions

### Available Actions

| Action | Method | Use Case |
|--------|--------|----------|
| ARP Correction | Gratuitous ARP | Counter ARP cache poisoning |
| TCP RST | Inject RST packet | Kill suspicious connections |
| WiFi Deauth | 802.11 deauth frame | Disconnect rogue/attacking device |
| Packet Drop | iptables/nftables | Silently block traffic |
| Rate Throttle | tc/nftables | Slow down instead of block |

### Defense Mode Levels

```rust
enum DefenseMode {
    Log,      // Detect and log only
    Alert,    // Log + push notifications
    Block,    // Log + push + execute defense actions
}
```

LLM can change mode via `defense.mode` RPC call.

## Network Interface Modes

### Promiscuous Mode (Ethernet)

Standard promiscuous mode to see all LAN traffic:
- Enable via socket options or libpcap
- See traffic not addressed to us
- Passive observation, no modification

### Monitor Mode (WiFi)

Native Rust implementation using nl80211:

```rust
// Using neli or netlink crates
fn set_monitor_mode(interface: &str) -> Result<()> {
    // 1. Bring interface down
    // 2. Set type to monitor via NL80211_CMD_SET_INTERFACE
    // 3. Bring interface up
    // 4. Optionally set channel
}
```

Required for:
- Seeing all WiFi frames (not just associated network)
- Injecting 802.11 management frames (deauth)
- Capturing probe requests from all devices

### 802.11 Frame Injection

Native deauth frame construction:

```rust
fn build_deauth_frame(bssid: MacAddr, client: MacAddr) -> Vec<u8> {
    // Radiotap header (minimal)
    // 802.11 header (type: management, subtype: deauth)
    // Reason code
}
```

Inject via raw socket on monitor mode interface.

## CLI Interface

```bash
# Guardian on Ethernet (promiscuous)
sudo widump --mode guardian -i eth0

# Guardian on WiFi (creates wlan0mon automatically)
sudo widump --mode guardian -i wlan0 --monitor

# Run daemon and guardian together
sudo widump --mode daemon -i eth0 &
sudo widump --mode guardian -i wlan0 --monitor --connect-daemon /tmp/widump.sock

# With WiFAKE push notifications
sudo widump --mode guardian -i eth0 --wifake-push http://wifake.local:8080/sensor/callback

# Set initial defense mode
sudo widump --mode guardian -i eth0 --defense-mode block
```

## Implementation Plan

### Phase 1: Promiscuous Mode + Threat Registry

1. Add promiscuous mode flag to capture initialization
2. Implement `ThreatRule` enum and storage
3. Add `threat.*` JSON-RPC methods
4. Integrate threat checking into packet analyzer
5. Wire up existing defense actions (ARP correct, TCP RST)

### Phase 2: Firewall Integration

1. Add iptables/nftables wrapper for packet dropping
2. Implement rate limiting via tc or nftables
3. Add `defense.block` and `defense.throttle` RPC methods

### Phase 3: WiFAKE Push Notifications

1. Implement push callback client
2. Add interest level filtering
3. Queue fallback for when push fails
4. Add `defense.push_endpoint` RPC method

### Phase 4: Native Monitor Mode

1. Implement nl80211 interface control via neli crate
2. Auto-create monitor mode interface (wlan0 → wlan0mon)
3. 802.11 frame parsing for management frames
4. Native deauth frame construction and injection

### Phase 5: Shared State (daemon + guardian)

1. Unix socket or shared memory for NetworkState
2. `--connect-daemon` flag for guardian to join existing daemon
3. Unified device/flow state across modes

## Dependencies

### New Crates

| Crate | Purpose |
|-------|---------|
| `neli` or `netlink-packet-route` | nl80211 for monitor mode |
| `nftables` or shell to `nft` | Firewall rules |
| `reqwest` (already have?) | Push notifications to WiFAKE |

### System Requirements

- Root privileges (already required)
- WiFi adapter supporting monitor mode (for WiFi guardian)
- Linux kernel with nl80211 support

## Security Considerations

- Guardian mode requires explicit opt-in (separate mode flag)
- Defense actions logged for audit trail
- LLM must authenticate to send commands (existing password auth)
- Rate limiting on defense actions to prevent self-DoS

## Success Criteria

1. Guardian can detect and block ARP spoofing in real-time
2. Guardian can detect port scans and RST the scanner
3. Guardian can put WiFi interface in monitor mode without aircrack-ng
4. Guardian can deauth a specified MAC from the network
5. WiFAKE LLM can register threats and receive push notifications
6. Daemon and guardian can share NetworkState when running together
