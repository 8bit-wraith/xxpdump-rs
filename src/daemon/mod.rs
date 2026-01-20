//! Daemon mode - LLM-queryable network sensor
//!
//! Captures packets, builds state, serves JSON-RPC, advertises via Avahi.
//! Active defense via packet injection.

pub mod analyzer;
pub mod avahi;
pub mod defense;
pub mod enrich;
pub mod rpc;
pub mod state;

use analyzer::{analyze_packet, ArpCache, ScanDetector};
use avahi::AvahiAdvertiser;
use defense::DefenseInjector;
use rpc::{start_rpc_server, SharedState};
use state::{DefenseMode, NetworkState};

use pcapture::Capture;
use pcapture::fs::pcapng::GeneralBlock;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Daemon configuration
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub interface: String,
    pub rpc_addr: String,
    pub advertise: bool,
    pub service_name: String,
    pub defense_mode: DefenseMode,
    pub filter: Option<String>,
    pub promisc: bool,
    pub buffer_size: usize,
    pub snaplen: usize,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            interface: "any".into(),
            rpc_addr: "0.0.0.0:12346".into(),
            advertise: true,
            service_name: format!("widump-{}", hostname()),
            defense_mode: DefenseMode::Log,
            filter: None,
            promisc: true,
            buffer_size: 163840,
            snaplen: 65535,
        }
    }
}

/// Run daemon mode
pub async fn run_daemon(config: DaemonConfig) -> anyhow::Result<()> {
    info!("Starting widump daemon on {}", config.interface);
    info!("RPC server: {}", config.rpc_addr);
    info!("Defense mode: {:?}", config.defense_mode);

    // Shared state
    let state: SharedState = Arc::new(RwLock::new(NetworkState::new()));
    state.write().await.defense_mode = config.defense_mode;

    // Avahi advertiser
    let mut avahi = AvahiAdvertiser::new(&config.service_name);
    if config.advertise {
        let port = config
            .rpc_addr
            .split(':')
            .last()
            .and_then(|p| p.parse().ok())
            .unwrap_or(12346);
        avahi.start(port).await?;
    }

    // Defense injector (if not "any" interface)
    let _injector = if config.interface != "any" {
        Some(Arc::new(tokio::sync::Mutex::new(DefenseInjector::new(
            &config.interface,
        ))))
    } else {
        warn!("Defense injection disabled on 'any' interface");
        None
    };

    // Start RPC server
    let rpc_state = state.clone();
    let rpc_addr = config.rpc_addr.clone();
    tokio::spawn(async move {
        if let Err(e) = start_rpc_server(&rpc_addr, rpc_state).await {
            error!("RPC server error: {}", e);
        }
    });

    // Capture loop
    let capture_state = state.clone();
    let capture_config = config.clone();

    tokio::task::spawn_blocking(move || {
        run_capture_loop(capture_config, capture_state);
    })
    .await?;

    // Cleanup
    avahi.stop().await;

    Ok(())
}

/// Blocking capture loop (runs in spawn_blocking)
#[cfg(feature = "libpnet")]
fn run_capture_loop(config: DaemonConfig, state: SharedState) {
    use pcapture::PcapByteOrder;

    // Create capture
    let mut cap = match Capture::new(&config.interface) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to open capture: {}", e);
            return;
        }
    };

    // Configure
    cap.set_promiscuous(config.promisc);
    cap.set_buffer_size(config.buffer_size);
    cap.set_snaplen(config.snaplen);
    cap.set_timeout(0.1);

    if let Some(ref filter) = config.filter {
        if let Err(e) = cap.set_filter(filter) {
            warn!("Failed to set filter '{}': {}", filter, e);
        }
    }

    info!("Capture active (libpnet), processing packets...");

    // Generate pcapng header for interface info
    let _pbo = PcapByteOrder::WiresharkDefault;

    // Analysis state (not shared)
    let mut arp_cache = ArpCache::new();
    let mut scan_detector = ScanDetector::default();

    // Main loop
    loop {
        match cap.next_as_pcapng() {
            Ok(block) => {
                // Extract raw packet data from Enhanced Packet Block
                if let GeneralBlock::EnhancedPacketBlock(epb) = block {
                    let raw = &epb.packet_data;

                    // Analyze packet
                    let alerts = {
                        let rt = tokio::runtime::Handle::current();
                        rt.block_on(async {
                            let mut state = state.write().await;
                            analyze_packet(raw, &mut state, &mut arp_cache, &mut scan_detector)
                        })
                    };

                    // Push alerts to state
                    if !alerts.is_empty() {
                        let rt = tokio::runtime::Handle::current();
                        rt.block_on(async {
                            let mut state = state.write().await;
                            for alert in alerts {
                                state.push_alert(
                                    alert.level,
                                    alert.category,
                                    alert.summary,
                                    alert.details,
                                );
                            }
                        });
                    }
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                if !err_str.contains("timed out") && !err_str.contains("timeout") {
                    debug!("Capture error: {}", e);
                }
            }
        }
    }
}

#[cfg(feature = "libpcap")]
fn run_capture_loop(config: DaemonConfig, state: SharedState) {
    // Create capture
    let mut cap = match Capture::new(&config.interface) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to open capture: {}", e);
            return;
        }
    };

    // Configure
    cap.set_promiscuous(config.promisc);
    cap.set_buffer_size(config.buffer_size);
    cap.set_snaplen(config.snaplen as i32);
    cap.set_timeout(100); // 100ms timeout

    if let Some(ref filter) = config.filter {
        cap.set_filter(filter);
    }

    info!("Capture active (libpcap), processing packets...");

    // Analysis state (not shared)
    let mut arp_cache = ArpCache::new();
    let mut scan_detector = ScanDetector::default();

    // Main loop
    loop {
        match cap.fetch_as_pcapng() {
            Ok(blocks) => {
                for block in blocks {
                    if let GeneralBlock::EnhancedPacketBlock(epb) = block {
                        let raw = &epb.packet_data;

                        // Analyze packet
                        let alerts = {
                            let rt = tokio::runtime::Handle::current();
                            rt.block_on(async {
                                let mut state = state.write().await;
                                analyze_packet(raw, &mut state, &mut arp_cache, &mut scan_detector)
                            })
                        };

                        // Push alerts to state
                        if !alerts.is_empty() {
                            let rt = tokio::runtime::Handle::current();
                            rt.block_on(async {
                                let mut state = state.write().await;
                                for alert in alerts {
                                    state.push_alert(
                                        alert.level,
                                        alert.category,
                                        alert.summary,
                                        alert.details,
                                    );
                                }
                            });
                        }
                    }
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                if !err_str.contains("timed out") && !err_str.contains("timeout") {
                    debug!("Capture error: {}", e);
                }
            }
        }
    }
}

/// Get hostname for service name
fn hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".into())
}
