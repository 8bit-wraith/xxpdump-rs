# RF-Sense: Distributed RF Signature Observatory

**Date:** 2026-01-20
**Status:** Design
**Related:** widump (network sensor), wifake (LLM brain), DSPradio (SDR)

## Overview

RF-Sense is a distributed sensor network for RF signature collection and behavioral fingerprinting. Each node specializes in a specific RF domain (WiFi, BLE, TPMS, keyfobs, mmWave) and reports to a central wifake brain that correlates observations across all sensors.

**Core Principle:** RF signatures identify individuals more reliably than cameras. A camera sees "a person"; RF-sense knows "this specific phone/car/watch has been here 847 times."

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         wifake.com (Cloud)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────────────────────┐   │
│  │ Signature   │  │ Location    │  │ Node Reputation           │   │
│  │ Database    │  │ History     │  │ & Trust Scoring           │   │
│  └─────────────┘  └─────────────┘  └───────────────────────────┘   │
│                              ▲                                      │
│                              │ HTTPS/WebSocket                      │
└──────────────────────────────┼──────────────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────────────┐
│                        wifake (Local Brain)                         │
│                    LLM-powered correlation engine                   │
│                         JSON-RPC + mDNS                             │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
       ┌───────────┬───────────┼───────────┬───────────┬─────────────┐
       │           │           │           │           │             │
  ┌────▼────┐ ┌────▼────┐ ┌────▼────┐ ┌────▼────┐ ┌────▼────┐ ┌─────▼─────┐
  │ widump  │ │rf-sense │ │rf-sense │ │rf-sense │ │rf-sense │ │ DSPradio  │
  │ WiFi/   │ │  BLE    │ │  TPMS   │ │ keyfob  │ │ mmWave  │ │  5.8GHz   │
  │Ethernet │ │         │ │ 315/433 │ │         │ │biometric│ │  drones   │
  │   Pi    │ │ UniFi   │ │RTL-SDR  │ │ Nooelec │ │XIAO ESP │ │  HackRF   │
  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └───────────┘
```

## Sensor Types

### 1. rf-sense-ble (UniFi AP / Pi with BT dongle)
- BLE advertisement scanning
- Bluetooth Classic discovery
- GATT service enumeration
- Device behavioral fingerprinting

**UniFi U6-LR Capabilities (verified):**
- ARM64 Cortex-A53 dual-core
- 250MB RAM free
- MediaTek mt_soc_wifi + btmtk_uart
- WiFi: `iwpriv ra0 get_site_survey` (55 networks visible)
- BLE: `btmw-test` with GATT client (requires stopping btservice)
- Promiscuous mode already enabled on interfaces

### 2. rf-sense-tpms (RTL-SDR 315/433MHz)
- TPMS sensor ID capture
- Vehicle identification by tire sensor set
- Arrival/departure logging
- Pressure/temperature telemetry

### 3. rf-sense-keyfob (Nooelec SDR)
- Rolling code capture (not decode - just signature)
- Car unlock event detection
- Replay attack alerting
- Keyfob behavioral patterns

### 4. rf-sense-mmwave (XIAO MR60BHA2 ESP32-C6)
- Breathing rate detection
- Heartbeat monitoring
- Presence without motion
- Stress indicator (elevated HR)

### 5. DSPradio integration (5.8GHz drone detection)
- FPV signal detection
- DroneID burst analysis
- Operator location correlation

## Signature Engine

MAC addresses are insufficient - devices randomize them. The signature engine builds behavioral fingerprints:

### Fingerprint Components

| Layer | Attributes |
|-------|------------|
| **Timing** | Beacon interval, jitter, rotation schedule, probe timing |
| **Power** | TX strength profile, battery-correlated changes |
| **Protocol** | Response patterns, connection behavior, supported features |
| **Payload** | Advertisement structure, manufacturer data format |
| **Correlation** | Co-appearing devices (phone + watch + earbuds) |

### Signature Hash Generation

```rust
struct DeviceSignature {
    // Timing characteristics
    beacon_interval_ms: f32,
    beacon_jitter_std: f32,
    mac_rotation_period_s: Option<u32>,

    // Power profile
    tx_power_dbm: i8,
    power_variance: f32,

    // Protocol behavior
    supported_services: Vec<u16>,  // BLE service UUIDs
    probe_ssids: Vec<String>,      // WiFi probe requests
    response_timing_ms: f32,

    // Manufacturer hints
    oui_prefix: [u8; 3],
    adv_data_pattern: Vec<u8>,
}

impl DeviceSignature {
    fn hash(&self) -> SignatureHash {
        // Stable hash that survives MAC rotation
        // Based on behavioral characteristics
    }
}
```

## Privacy & Transparency Model

### User Rights (GDPR-compliant by design)

1. **Right to Access** - Any user can query all observations of their signature
2. **Right to Deletion** - Full purge of historical data
3. **Right to Opt-Out** - Blocklist signature from future recording
4. **Right to Portability** - Download complete history

### Consent Zones

```
┌─────────────────────────────────────────────────────────────┐
│                    RECORDING ZONES                          │
│                                                             │
│   🏠 Private node (homeowner's rules)                      │
│      → Owner controls retention policy                      │
│                                                             │
│   🏪 Declared zone (establishment with sticker)            │
│      → "RF signatures recorded - wifake.com"               │
│      → Enter = consent (like credit card TOS)              │
│                                                             │
│   🚶 Public space                                          │
│      → Node owner's discretion                             │
│      → Opt-out users: preliminary data dropped             │
└─────────────────────────────────────────────────────────────┘
```

### Opt-Out Visitor Notification

When an opted-out individual approaches a private node:

```
┌─────────────────────────────────────────┐
│  🏠 Your Home Node                      │
│                                         │
│  ⚠️  OPTED-OUT VISITOR DETECTED         │
│                                         │
│  Unknown individual near your property  │
│  They have chosen not to be identified  │
│                                         │
│  [Acknowledge]  [Heighten Alert Level]  │
└─────────────────────────────────────────┘
```

### Deletion Timeline

1. User requests deletion via wifake.com
2. Signature added to global opt-out bloom filter
3. Nodes sync bloom filter, stop recording that signature
4. Historical data purged within 30 days
5. User can verify deletion completed

## Node Reputation System

Observations are weighted by node trustworthiness:

### Reputation Factors

| Factor | Weight | Description |
|--------|--------|-------------|
| **Uptime** | 20% | Consistent online presence |
| **Corroboration** | 40% | Other nodes confirm sightings |
| **Accuracy** | 30% | No flagged false positives |
| **Age** | 10% | Time since registration |

### Observation Record

```json
{
  "signature_hash": "a1b2c3d4e5f6...",
  "location": {
    "lat": 35.123456,
    "lon": -80.654321,
    "accuracy_m": 10
  },
  "timestamp": "2026-01-20T14:32:00Z",
  "node_id": "node_abc123",
  "node_reputation": 94,
  "confidence": 0.87,
  "peer_attestations": [
    {"node_id": "node_def456", "signature": "..."}
  ]
}
```

## Cryptographic Verification

Prevents replay attacks and observation forgery:

```rust
struct SignedObservation {
    observation: Observation,

    // Timestamp verification
    timestamp_bucket: u64,        // 5-minute granularity
    global_epoch_key: [u8; 32],   // Rotates hourly

    // Node signature
    node_signature: [u8; 64],     // Ed25519

    // Peer attestations (nearby nodes co-sign)
    peer_signatures: Vec<PeerAttestation>,
}

struct PeerAttestation {
    node_id: NodeId,
    signature: [u8; 64],
    distance_estimate_m: Option<f32>,
}
```

### Attack Prevention

| Attack | Defense |
|--------|---------|
| Replay old data | Timestamp bucket expired (5-min windows) |
| Forge timestamps | Global epoch key unknown to attacker |
| Single malicious node | Peer attestation required for high-trust |
| Mass fabrication | Peers must be geographically plausible |

## Use Cases

### 1. Security Monitoring
- Unknown device near property → alert
- Known device (family) → log arrival
- Opted-out visitor → heightened awareness

### 2. Alibi Generation
- "I was at the grocery store at 3pm"
- User can prove presence via their own signature history

### 3. Fraud Detection
```
Signature 0xA1B2C3 (verified: John, Ohio)
├── Last known: Columbus, OH - 2 hours ago
├── Now appearing: Lagos, Nigeria
├── Communication stress markers: ELEVATED
└── 🚨 ANOMALY: Impossible travel + stress
```

### 4. Law Enforcement Support
- Reduce investigation time with RF evidence
- Signature trail provides witness-like data
- Node reputation indicates data reliability

### 5. Stalker Detection
- User queries: "What signatures keep appearing near me?"
- Pattern analysis reveals persistent followers

## Protocol: Node ↔ wifake Communication

### Discovery
- mDNS: `_wifake._tcp` service advertisement
- Nodes announce capabilities and sensor types

### Interest Levels (inherited from widump)

| Level | Name | Push Behavior |
|-------|------|---------------|
| 0 | critical | Immediate push |
| 1 | alert | Push within 5s |
| 2 | change | On-request |
| 3 | summary | On-request |
| 4 | debug | On-request |

### JSON-RPC Methods

```
# Node → wifake
observation.submit      # Submit signed observation
observation.batch       # Submit batch of observations
node.heartbeat          # Keepalive with stats

# wifake → Node
node.configure          # Update node settings
blocklist.sync          # Sync opt-out bloom filter
threat.register         # Register threat signature
```

## Implementation Plan

### Phase 1: rf-sense-ble (UniFi)
1. Cross-compile Rust for aarch64-unknown-linux-musl
2. Implement iwpriv wrapper for WiFi scanning
3. Implement btmw-test wrapper for BLE (or direct btmtk)
4. JSON-RPC server matching widump interface
5. mDNS advertisement

### Phase 2: rf-sense-tpms
1. RTL-SDR integration via rtl_433 or native Rust
2. TPMS packet decoding (315/433MHz)
3. Vehicle signature building (4 sensors = 1 vehicle)

### Phase 3: wifake.com Cloud
1. Observation ingestion API
2. Signature database with location history
3. User portal (access/delete/opt-out)
4. Node reputation scoring

### Phase 4: Additional Sensors
- keyfob detection
- mmWave biometric integration
- DSPradio drone correlation

## Cross-Compilation for UniFi

```bash
# Target: UniFi U6-LR (ARM64)
rustup target add aarch64-unknown-linux-musl

# Build
cargo build --release --target aarch64-unknown-linux-musl

# Deploy
scp target/aarch64-unknown-linux-musl/release/rf-sense u6:/tmp/
ssh u6 "chmod +x /tmp/rf-sense && /tmp/rf-sense --help"
```

## File Structure

```
rf-sense/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config.rs
│   ├── signature/
│   │   ├── mod.rs
│   │   ├── fingerprint.rs
│   │   └── hash.rs
│   ├── sensors/
│   │   ├── mod.rs
│   │   ├── ble.rs          # BLE scanning
│   │   ├── wifi.rs         # WiFi probe/survey
│   │   ├── tpms.rs         # TPMS decoding
│   │   └── unifi.rs        # UniFi-specific iwpriv
│   ├── rpc/
│   │   ├── mod.rs
│   │   ├── server.rs       # JSON-RPC server
│   │   └── methods.rs
│   └── crypto/
│       ├── mod.rs
│       ├── signing.rs      # Ed25519 signatures
│       └── attestation.rs  # Peer attestation
└── tests/
    └── integration.rs
```

## Dependencies

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = "0.3"

# Crypto
ed25519-dalek = "2"
blake3 = "1"

# Networking
jsonrpc-core = "18"
mdns-sd = "0.10"

# BLE (optional, for Pi with bluez)
btleplug = { version = "0.11", optional = true }

# SDR (optional, for TPMS)
rtlsdr = { version = "0.1", optional = true }
```

## Success Criteria

1. rf-sense runs on UniFi U6-LR with <50MB RAM usage
2. BLE scan detects devices within 5 seconds
3. WiFi survey matches UniFi controller data
4. Signatures persist across MAC rotations
5. wifake.com user can view/delete their data
6. Node reputation accurately reflects trustworthiness
