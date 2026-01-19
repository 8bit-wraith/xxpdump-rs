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

Four operational modes managed in `src/main.rs`:

| Mode | File | Purpose |
|------|------|---------|
| local | `local.rs` | Capture packets from local interfaces |
| client | `client.rs` | Capture locally, stream to remote server via TCP |
| server | `server.rs` | Receive packets from clients, write to files |
| - | `split.rs` | File rotation logic (time/size/count-based) |

**Data flow:**
- Local: `Capture → pcapng blocks → SplitRule → file(s)`
- Client: `Capture → pcapng blocks → bincode serialize → TCP → server`
- Server: `TCP → bincode deserialize → SplitRule → file(s)`

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
