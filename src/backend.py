#!/usr/bin/env python3
"""
ThreatGuard-AI Dashboard Backend

Flask web server providing real-time DDoS detection dashboard.
Runs NFStream capture in background thread and serves status via API.

Requires root/sudo privileges for network capture.

Author: ThreatGuard-AI Team
"""

import os
import sys
import argparse
import threading
import time
import signal
from pathlib import Path
from datetime import datetime
from typing import Dict

import numpy as np
import joblib
from flask import Flask, render_template, jsonify
from nfstream import NFStreamer

# =============================================================================
# CONFIGURATION
# =============================================================================

app = Flask(__name__, template_folder='../templates')

# Global state
status = {
    'current_status': 'INITIALIZING',
    'attack_type': None,
    'total_flows': 0,
    'attack_count': 0,
    'benign_count': 0,
    'last_attack_time': None,
    'uptime_seconds': 0,
    'consecutive_benign': 0,
    'is_capturing': False,
    'last_flow_time': None,
    'interface': 'unknown',
    'attack_logs': []
}

# Thread control
capture_thread = None
running = True
start_time = datetime.now()

# Model artifacts (loaded on startup)
model = None
scaler = None
feature_names = None
label_encoder = None

# =============================================================================
# FEATURE EXTRACTION - MUST BE IDENTICAL TO extract_features.py
# =============================================================================

FEATURE_NAMES = [
    'flow_duration_ms',
    'total_fwd_packets',
    'total_bwd_packets',
    'flow_bytes_per_sec',
    'flow_packets_per_sec',
    'fwd_packet_length_mean',
    'bwd_packet_length_mean',
    'flow_iat_mean',
    'fwd_packet_length_max',
    'bwd_packet_length_max',
    'fwd_iat_mean',
    'bwd_iat_mean'
]


def extract_flow_features(flow) -> Dict:
    """Extract features from a single flow."""
    duration = max(flow.bidirectional_duration_ms, 1)
    
    return {
        'flow_duration_ms': duration,
        'total_fwd_packets': flow.src2dst_packets,
        'total_bwd_packets': flow.dst2src_packets,
        'flow_bytes_per_sec': (flow.bidirectional_bytes / duration) * 1000,
        'flow_packets_per_sec': (flow.bidirectional_packets / duration) * 1000,
        'fwd_packet_length_mean': flow.src2dst_mean_ps if flow.src2dst_mean_ps else 0,
        'bwd_packet_length_mean': flow.dst2src_mean_ps if flow.dst2src_mean_ps else 0,
        'flow_iat_mean': flow.bidirectional_mean_piat_ms if flow.bidirectional_mean_piat_ms else 0,
        'fwd_packet_length_max': flow.src2dst_max_ps if flow.src2dst_max_ps else 0,
        'bwd_packet_length_max': flow.dst2src_max_ps if flow.dst2src_max_ps else 0,
        'fwd_iat_mean': flow.src2dst_mean_piat_ms if flow.src2dst_mean_piat_ms else 0,
        'bwd_iat_mean': flow.dst2src_mean_piat_ms if flow.dst2src_mean_piat_ms else 0
    }


def load_model(models_dir: Path):
    """Load trained model and artifacts."""
    global model, scaler, feature_names, label_encoder
    
    model = joblib.load(models_dir / 'ddos_model.pkl')
    scaler = joblib.load(models_dir / 'scaler.pkl')
    feature_names = joblib.load(models_dir / 'feature_names.pkl')
    label_encoder = joblib.load(models_dir / 'label_encoder.pkl')
    
    print(f"✓ Model loaded. Classes: {list(label_encoder.classes_)}")


def capture_thread_func(interface: str, min_packets: int = 3):
    """Background thread for network capture and detection."""
    global running, status
    
    status['is_capturing'] = True
    status['current_status'] = 'SAFE'
    status['interface'] = interface
    
    print(f"Starting capture on {interface}...")
    
    try:
        streamer = NFStreamer(
            source=interface,
            statistical_analysis=True,
            idle_timeout=10,
            active_timeout=30
        )
        
        for flow in streamer:
            if not running:
                break
            
            # Skip flows with too few packets
            if flow.bidirectional_packets < min_packets:
                continue
            
            # Extract features
            features = extract_flow_features(flow)
            
            # Create feature array
            feature_array = np.array([[features[f] for f in FEATURE_NAMES]])
            
            # Handle NaN/Inf
            if np.any(np.isnan(feature_array)) or np.any(np.isinf(feature_array)):
                continue
            
            # Scale and predict
            feature_array_scaled = scaler.transform(feature_array)
            prediction = model.predict(feature_array_scaled)[0]
            label = label_encoder.classes_[prediction]
            
            # Update status
            status['total_flows'] += 1
            status['last_flow_time'] = datetime.now().isoformat()
            
            if label == 'BENIGN':
                status['benign_count'] += 1
                status['consecutive_benign'] += 1
                
                # Return to SAFE after 20 consecutive benign flows
                if status['consecutive_benign'] >= 20:
                    status['current_status'] = 'SAFE'
                    status['attack_type'] = None
            else:
                # Attack detected
                status['attack_count'] += 1
                status['consecutive_benign'] = 0
                status['current_status'] = 'UNDER_ATTACK'
                status['attack_type'] = label
                status['last_attack_time'] = datetime.now().isoformat()
                
                # Add to logs
                log_entry = {
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'type': label,
                    'src': f"{flow.src_ip}:{flow.src_port}",
                    'dst': f"{flow.dst_ip}:{flow.dst_port}",
                    'packets': flow.bidirectional_packets
                }
                status['attack_logs'].insert(0, log_entry)
                # Keep only last 50 logs
                if len(status['attack_logs']) > 50:
                    status['attack_logs'].pop()
    
    except Exception as e:
        print(f"Capture error: {e}")
        status['current_status'] = 'ERROR'
    
    status['is_capturing'] = False


# =============================================================================
# FLASK ROUTES
# =============================================================================

@app.route('/')
def dashboard():
    """Serve the dashboard page."""
    return render_template('dashboard.html')


@app.route('/api/status')
def get_status():
    """Return current detection status as JSON."""
    global start_time
    
    # Update uptime
    status['uptime_seconds'] = int((datetime.now() - start_time).total_seconds())
    
    return jsonify(status)


# =============================================================================
# MAIN
# =============================================================================

def signal_handler(signum, frame):
    """Handle shutdown signals."""
    global running
    print("\nShutting down...")
    running = False


def main():
    """Main function to start the dashboard server."""
    global capture_thread, start_time
    
    parser = argparse.ArgumentParser(
        description='ThreatGuard-AI Dashboard Server'
    )
    parser.add_argument(
        'interface',
        nargs='?',
        default='enp11s0',
        help='Network interface to capture from (default: enp11s0)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Server port (default: 5000)'
    )
    parser.add_argument(
        '--host',
        type=str,
        default='0.0.0.0',
        help='Server host (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--models-dir',
        type=str,
        default='models',
        help='Directory containing trained model (default: models)'
    )
    
    args = parser.parse_args()
    
    # Resolve paths
    script_dir = Path(__file__).parent.parent
    models_dir = Path(args.models_dir)
    if not models_dir.is_absolute():
        models_dir = script_dir / models_dir
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("Error: Root privileges required for network capture.")
        print(f"Run with: sudo {sys.executable} {' '.join(sys.argv)}")
        sys.exit(1)
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║           THREATGUARD-AI - Dashboard Server                   ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Load model
    print("Loading model...")
    try:
        load_model(models_dir)
    except Exception as e:
        print(f"Error loading model: {e}")
        print("Make sure you've trained the model first.")
        sys.exit(1)
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start capture thread
    start_time = datetime.now()
    capture_thread = threading.Thread(
        target=capture_thread_func,
        args=(args.interface,),
        daemon=True
    )
    capture_thread.start()
    
    print(f"✓ Capturing on: {args.interface}")
    print(f"✓ Dashboard: http://localhost:{args.port}")
    print(f"\nPress Ctrl+C to stop\n")
    
    # Start Flask server
    try:
        app.run(
            host=args.host,
            port=args.port,
            debug=False,
            use_reloader=False
        )
    except Exception as e:
        print(f"Server error: {e}")


if __name__ == '__main__':
    main()
