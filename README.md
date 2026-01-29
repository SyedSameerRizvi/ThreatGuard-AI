# ThreatGuard-AI 🛡️

**Real-Time DDoS Detection System**

A complete end-to-end DDoS detection system that uses machine learning to detect network attacks in real-time. Built with NFStream for network traffic analysis and Random Forest for classification.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Dataset Information](#dataset-information)
- [Troubleshooting](#troubleshooting)

---

## Overview

ThreatGuard-AI is a machine learning-based DDoS detection system designed for:

1. **Feature Extraction**: Processes PCAP files using NFStream to extract 12 flow-based features
2. **Model Training**: Trains a Random Forest classifier to detect benign vs. attack traffic
3. **Live Detection**: Captures network traffic in real-time and classifies flows
4. **Web Dashboard**: Provides a modern UI showing network security status

**Attack Types Detected:**
- ✅ BENIGN (normal traffic)
- 🚨 UDP Flood attacks

---

## Features

- 🔍 **NFStream-based feature extraction** - Consistent features for training and deployment
- 🤖 **Random Forest classifier** - Balanced, high-accuracy detection
- ⚡ **Real-time detection** - Live network monitoring
- 🌐 **Web dashboard** - Modern, responsive status display
- 📊 **Visualization** - Confusion matrix, ROC curves, feature importance
- 📝 **Logging** - Complete detection logs

---

## System Requirements

- **OS**: Ubuntu Linux 20.04+
- **Python**: 3.8+
- **Memory**: 4GB+ RAM (for processing large PCAPs)
- **Privileges**: Root/sudo for live capture

---

## Installation

### 1. Clone or Navigate to Project

```bash
cd ~/Desktop/threatguard-ai
```

### 2. Run Setup Script

```bash
chmod +x setup.sh
./setup.sh
```

This will:
- Create virtual environment
- Install all dependencies
- Verify NFStream installation
- Create directory structure

### 3. Verify Installation

```bash
source venv/bin/activate
python -c "import nfstream; print('NFStream OK')"
```

---

## Usage

### Step 1: Extract Features from PCAP

```bash
source venv/bin/activate
python src/extract_features.py
```

**Options:**
- `--pcap-dir PATH` - Directory containing PCAP files
- `--output PATH` - Output CSV path
- `--max-files N` - Limit number of PCAPs to process

**Output:** `data/processed/features.csv`

### Step 2: Train Model

```bash
python src/train_model.py
```

**Options:**
- `--n-estimators N` - Number of trees (default: 100)
- `--max-depth N` - Max tree depth (default: 20)

**Output:**
- `models/ddos_model.pkl` - Trained model
- `models/scaler.pkl` - Feature scaler
- `logs/confusion_matrix.png` - Confusion matrix
- `logs/roc_curves.png` - ROC curves

### Step 3: Run Live Detection (Console)

```bash
sudo venv/bin/python src/capture_live.py enp11s0
```

Replace `enp11s0` with your network interface.

**To find your interface:**
```bash
ip a
```

### Step 4: Run Dashboard

```bash
sudo venv/bin/python src/backend.py enp11s0
```

Then open: **http://localhost:5000**

---

## Project Structure

```
threatguard-ai/
├── data/
│   ├── PCAP-03-11/          # PCAP files (CIC-DDoS2019)
│   └── processed/           # Extracted features
├── models/
│   ├── ddos_model.pkl       # Trained model
│   ├── scaler.pkl           # Feature scaler
│   └── feature_names.pkl    # Feature list
├── src/
│   ├── extract_features.py  # Feature extraction
│   ├── train_model.py       # Model training
│   ├── capture_live.py      # Live detection
│   └── backend.py           # Flask server
├── templates/
│   └── dashboard.html       # Web UI
├── logs/
│   ├── training.log         # Training logs
│   ├── detections.log       # Detection logs
│   └── confusion_matrix.png # Visualizations
├── requirements.txt
├── setup.sh
└── README.md
```

---

## Dataset Information

**Dataset:** CIC-DDoS2019 Day 2 (SAT-03-11-2018)

| Time Range | Label |
|------------|-------|
| Before 18:01 | BENIGN |
| After 18:01 | UDP Flood |

**Features Extracted (12):**
1. `flow_duration_ms` - Flow duration
2. `total_fwd_packets` - Forward packets
3. `total_bwd_packets` - Backward packets
4. `flow_bytes_per_sec` - Bytes per second
5. `flow_packets_per_sec` - Packets per second
6. `fwd_packet_length_mean` - Mean forward packet size
7. `bwd_packet_length_mean` - Mean backward packet size
8. `flow_iat_mean` - Mean inter-arrival time
9. `fwd_packet_length_max` - Max forward packet size
10. `bwd_packet_length_max` - Max backward packet size
11. `fwd_iat_mean` - Forward IAT mean
12. `bwd_iat_mean` - Backward IAT mean

---

## Troubleshooting

### NFStream Installation Failed

```bash
sudo apt-get install libpcap-dev
pip install nfstream
```

### Permission Denied for Live Capture

Live capture requires root:
```bash
sudo venv/bin/python src/capture_live.py
```

### No Flows Detected

- Check interface name: `ip a`
- Ensure network has traffic
- Try with lower min-packets: `--min-packets 2`

### Model Not Found

Run training first:
```bash
python src/train_model.py
```

---

## Testing Attack Detection

### Using hping3 (simulate attacks)

```bash
# Install hping3
sudo apt-get install hping3

# Simulate UDP flood (run in another terminal)
sudo hping3 --udp -p 80 --flood <target-ip>

# Simulate SYN flood
sudo hping3 -S -p 80 --flood <target-ip>
```

### Using tcpreplay (replay PCAPs)

```bash
sudo apt-get install tcpreplay
sudo tcpreplay -i enp11s0 data/PCAP-03-11/SAT-03-11-2018_01
```

---

## FYP Demo Script

1. Start dashboard: `sudo venv/bin/python src/backend.py`
2. Open browser: `http://localhost:5000`
3. Show "NETWORK SAFE" status
4. In another terminal, start UDP flood test
5. Dashboard should switch to "UNDER ATTACK - UDP"
6. Stop attack, dashboard returns to "NETWORK SAFE"

---

## License

Final Year Project - Educational Use Only

---

## Author

ThreatGuard-AI Team - 2024
