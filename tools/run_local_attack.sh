#!/bin/bash
# Local SYN Flood Attack Script (10 Minutes)
# Uses hping3 to attack localhost and tcpdump to capture it

PCAP_FILE="/home/hannan/Desktop/threatguard-ai/data/syn_attack_local.pcap"
DURATION=600  # 10 minutes

echo "============================================"
echo "    STARTING LOCAL SYN FLOOD CAPTURE        "
echo "============================================"
echo "Duration: $DURATION seconds"
echo "Target: 127.0.0.1 (Localhost)"
echo "Output: $PCAP_FILE"

# 1. Start tcpdump on Loopback interface
echo "[1/3] Starting tcpdump on 'lo' interface..."
sudo tcpdump -i lo -w "$PCAP_FILE" > /dev/null 2>&1 &
DUMP_PID=$!
echo "      -> PID: $DUMP_PID"

sleep 2

# 2. Start hping3 attack
# Using -i u10 = 100,000 packets/sec (High intensity but controlled)
# Total size est: ~4GB for 10 mins
echo "[2/3] Starting hping3 SYN flood (100k pps)..."
sudo hping3 -S -p 80 -i u10 127.0.0.1 > /dev/null 2>&1 &
ATTACK_PID=$!
echo "      -> PID: $ATTACK_PID"

# 3. Wait for duration
echo "[3/3] Running for $DURATION seconds. Do not close terminal..."
sleep $DURATION

# 4. Cleanup
echo "--------------------------------------------"
echo "Time's up! Stopping processes..."
sudo kill $ATTACK_PID
sudo kill $DUMP_PID
sleep 2
echo "Done! Capture saved to $PCAP_FILE"
