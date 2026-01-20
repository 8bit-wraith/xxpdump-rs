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

#[test]
#[ignore] // Requires running daemon
fn test_threat_enable_disable() {
    let mut stream = TcpStream::connect("127.0.0.1:12346").expect("Daemon not running");

    // Add a threat rule
    let response = send_rpc(&mut stream, "threat.add", serde_json::json!({
        "type": "arp_spoof"
    }));
    let threat_id = response["result"]["threat_id"].as_u64().unwrap();

    // Disable it
    let response = send_rpc(&mut stream, "threat.enable", serde_json::json!({
        "id": threat_id,
        "enabled": false
    }));
    assert_eq!(response["result"]["enabled"].as_bool().unwrap(), false);

    // Re-enable it
    let response = send_rpc(&mut stream, "threat.enable", serde_json::json!({
        "id": threat_id,
        "enabled": true
    }));
    assert_eq!(response["result"]["enabled"].as_bool().unwrap(), true);

    // Cleanup
    send_rpc(&mut stream, "threat.remove", serde_json::json!({"id": threat_id}));
}

#[test]
#[ignore] // Requires running daemon
fn test_threat_actions_history() {
    let mut stream = TcpStream::connect("127.0.0.1:12346").expect("Daemon not running");

    // Get actions history (may be empty)
    let response = send_rpc(&mut stream, "threat.actions", serde_json::json!({
        "limit": 10
    }));

    // Should return an array (even if empty)
    assert!(response["result"].is_array());
}
