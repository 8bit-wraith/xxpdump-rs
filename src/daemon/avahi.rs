//! Avahi/mDNS service advertisement
//! Advertises _widump._tcp for discovery

use std::process::Stdio;
use tokio::process::{Child, Command};
use tracing::{info, warn, error};

/// Avahi advertiser handle
pub struct AvahiAdvertiser {
    child: Option<Child>,
    service_name: String,
}

impl AvahiAdvertiser {
    /// Create new advertiser (doesn't start yet)
    pub fn new(name: &str) -> Self {
        Self {
            child: None,
            service_name: name.to_string(),
        }
    }

    /// Start advertising via avahi-publish
    pub async fn start(&mut self, port: u16) -> anyhow::Result<()> {
        // Use avahi-publish-service
        // avahi-publish-service "widump-pi" "_widump._tcp" 12346 "version=0.4" "role=sensor"

        let child = Command::new("avahi-publish-service")
            .arg(&self.service_name)
            .arg("_widump._tcp")
            .arg(port.to_string())
            .arg("version=0.4")
            .arg("role=sensor")
            .arg("caps=capture,defense")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn();

        match child {
            Ok(c) => {
                info!("Avahi advertising {} on _widump._tcp:{}", self.service_name, port);
                self.child = Some(c);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to start avahi-publish: {} - continuing without mDNS", e);
                Ok(()) // Non-fatal, continue without mDNS
            }
        }
    }

    /// Stop advertising
    pub async fn stop(&mut self) {
        if let Some(ref mut child) = self.child {
            if let Err(e) = child.kill().await {
                error!("Failed to stop avahi-publish: {}", e);
            }
        }
        self.child = None;
    }

    /// Check if advertising
    pub fn is_running(&self) -> bool {
        self.child.is_some()
    }
}

impl Drop for AvahiAdvertiser {
    fn drop(&mut self) {
        // Try sync kill on drop
        if let Some(ref mut child) = self.child {
            let _ = child.start_kill();
        }
    }
}

/// Discover other widump instances via avahi-browse
pub async fn discover_peers() -> anyhow::Result<Vec<PeerInfo>> {
    let output = Command::new("avahi-browse")
        .arg("-t") // terminate after list
        .arg("-r") // resolve
        .arg("-p") // parseable
        .arg("_widump._tcp")
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut peers = Vec::new();

    for line in stdout.lines() {
        // Format: +;eth0;IPv4;widump-pi;_widump._tcp;local;hostname;192.168.1.x;12346;...
        let parts: Vec<&str> = line.split(';').collect();
        if parts.len() >= 9 && parts[0] == "=" {
            peers.push(PeerInfo {
                name: parts[3].to_string(),
                host: parts[6].to_string(),
                ip: parts[7].to_string(),
                port: parts[8].parse().unwrap_or(12346),
            });
        }
    }

    Ok(peers)
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub name: String,
    pub host: String,
    pub ip: String,
    pub port: u16,
}
