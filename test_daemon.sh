#!/bin/bash
# Test widump daemon JSON-RPC

HOST="${1:-127.0.0.1}"
PORT="${2:-12346}"

echo "Testing widump daemon at $HOST:$PORT"
echo

# Ping test
echo '{"method":"ping","id":1}' | nc -q1 $HOST $PORT
echo

# Status
echo '{"method":"status","id":2}' | nc -q1 $HOST $PORT
echo

# Summary
echo '{"method":"summary","params":{"window":"1m"},"id":3}' | nc -q1 $HOST $PORT
echo

# Device list
echo '{"method":"device.list","id":4}' | nc -q1 $HOST $PORT
echo

# Alerts
echo '{"method":"alerts","params":{"since":"5m"},"id":5}' | nc -q1 $HOST $PORT
echo
