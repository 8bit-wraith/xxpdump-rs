# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

widump-rs is a Rust-based packet capture tool, a modern alternative to tcpdump. Key differentiators:
- Remote packet capture via client-server architecture
- Flexible file splitting (time, size, packet count)
- Dual backend support (libpnet and libpcap)

## Build Commands

```bash
# Build with default libpnet backend
cargo build --release

# Build with libpcap backend
cargo build --release --features libpcap

# Install from crates.io
cargo install widump --features "libpnet"

# Run tests
cargo test

# Run a single test
cargo test test_name
```

**Note:** Packet capture requires root privileges. The `.cargo/config.toml` configures `sudo -E` as the runner.

## Architecture

Five operational modes managed in `src/main.rs`:

| Mode | File | Purpose |
|------|------|---------|
| local | `local.rs` | Capture packets from local interfaces |
| client | `client.rs` | Capture locally, stream to remote server via TCP |
| server | `server.rs` | Receive packets from clients, write to files |
| daemon | `daemon/` | LLM-queryable sensor with JSON-RPC + Avahi |
| - | `split.rs` | File rotation logic (time/size/count-based) |

**Data flow:**
- Local: `Capture → pcapng blocks → SplitRule → file(s)`
- Client: `Capture → pcapng blocks → bincode serialize → TCP → server`
- Server: `TCP → bincode deserialize → SplitRule → file(s)`
- Daemon: `Capture → analyze → NetworkState → JSON-RPC queries`

**Remote protocol:** Custom binary format over TCP:
- 4 bytes length (big-endian u32) + bincode-encoded `PcapNgTransport`
- Simple password authentication before streaming

**Split rules** (`split.rs`): Four variants - `SplitRuleNone` (no rotation), `SplitRuleRotate` (time-based), `SplitRuleFileSize`, `SplitRuleCount`. All implement buffered writes (~100 packets) and proper pcapng header generation for each new file.

**Packet printing**: When no `-w` file is specified, packets print to console via `PacketPrinter` in `main.rs`. Time display modes: `-t` (none), `-tt` (epoch), `-ttt` (delta from previous), `-tttt` (human-readable), `-ttttt` (delta from first). Flags `-S` shows raw TCP sequence numbers, `-e` shows Ethernet layer.

**Global state**: Uses `LazyLock<Arc<Mutex<>>>` for thread-safe packet counters (`PACKETS_CAPTURED`, `PACKETS_SERVER_TOTAL_RECVED`). Statistics logged on Ctrl+C via `ctrlc` handler.

## Key Dependencies

- `pcapture` - Packet capture wrapper (project's own crate)
- `tokio` - Async runtime for client/server modes
- `clap` (derive) - CLI argument parsing
- `bincode` - Binary serialization for remote protocol
- `pnet` - Packet parsing

## Feature Flags

- `libpnet` (default) - Use libpnet for capture
- `libpcap` - Use libpcap for capture (requires libpcap installed). Supports "any" pseudo-device.

## Windows Development

Requires npcap SDK. Set `$env:LIB` to point to `Packet.lib` location before building.

## Daemon Mode (LLM Sensor)

For WiFAKE integration. Captures packets, analyzes locally, serves JSON-RPC on port 12346.

```bash
# Start daemon
sudo widump --mode daemon -i eth0

# With active defense
sudo widump --mode daemon -i eth0 --defense-mode block
```

**Daemon modules** (`src/daemon/`):
- `state.rs` - NetworkState, FlowKey, DeviceProfile, alerts, watches
- `analyzer.rs` - Packet → flow/device updates, ARP spoof & port scan detection
- `rpc.rs` - JSON-RPC server (TCP)
- `avahi.rs` - mDNS advertisement (`_widump._tcp`)
- `defense.rs` - Active packet injection (ARP correction, TCP RST)

**JSON-RPC Methods:**
| Method | Purpose |
|--------|---------|
| `summary` | Device count, top talkers, protocol distribution |
| `alerts` | Recent security alerts |
| `device.profile` | Details for specific MAC |
| `device.list` | All known devices |
| `watch.add` | Add LLM-defined watch rule |
| `defense.mode` | Set defense level (log/alert/block) |
| `defense.block` | Block specific MAC/IP |

**Interest Levels** (alert severity):
| Level | Name | Push? |
|-------|------|-------|
| 0 | critical | immediate |
| 1 | alert | <5s |
| 2 | change | on-request |
| 3 | summary | on-request |
| 4 | debug | on-request |
