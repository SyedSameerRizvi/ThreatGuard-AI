#!/usr/bin/env python3
"""
ThreatGuard-AI Live Capture Script

Captures live network traffic and detects DDoS attacks in real-time
using the trained model.

Requires root/sudo privileges for network capture.

Author: ThreatGuard-AI Team
"""

import os
import sys
import argparse
import logging
import signal
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

import numpy as np
import joblib
from nfstream import NFStreamer

# ANSI color codes for console output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# Global flag for graceful shutdown
running = True

# Configure logging
def setup_logging(log_file: Path):
    """Setup logging to file and console."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
        ]
    )
    return logging.getLogger(__name__)


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
    """
    Extract features from a single flow.
    
    CRITICAL: This function MUST be identical to the one in extract_features.py
    """
    duration = max(flow.bidirectional_duration_ms, 1)
    
    features = {
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
    
    return features


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully."""
    global running
    print(f"\n{Colors.YELLOW}Shutting down gracefully...{Colors.RESET}")
    running = False


def load_model(models_dir: Path):
    """Load trained model and artifacts."""
    model = joblib.load(models_dir / 'ddos_model.pkl')
    scaler = joblib.load(models_dir / 'scaler.pkl')
    feature_names = joblib.load(models_dir / 'feature_names.pkl')
    label_encoder = joblib.load(models_dir / 'label_encoder.pkl')
    
    return model, scaler, feature_names, label_encoder


def print_banner():
    """Print application banner."""
    print(f"""
{Colors.BLUE}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║           THREATGUARD-AI - Live DDoS Detection                ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}""")


def print_detection(flow, prediction: str, confidence: float, is_attack: bool):
    """Print detection result with colors."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    src = f"{flow.src_ip}:{flow.src_port}"
    dst = f"{flow.dst_ip}:{flow.dst_port}"
    
    if is_attack:
        status = f"{Colors.RED}🚨 {prediction} ATTACK{Colors.RESET}"
        color = Colors.RED
    else:
        status = f"{Colors.GREEN}✅ BENIGN{Colors.RESET}"
        color = Colors.GREEN
    
    print(f"[{timestamp}] {color}Flow:{Colors.RESET} {src} → {dst}")
    print(f"             {status} (confidence: {confidence:.1f}%)")
    print(f"             Packets: {flow.bidirectional_packets}, "
          f"Bytes: {flow.bidirectional_bytes}, "
          f"Duration: {flow.bidirectional_duration_ms:.0f}ms")
    print()


def main():
    """Main function for live capture and detection."""
    global running
    
    parser = argparse.ArgumentParser(
        description='Live DDoS detection using trained model'
    )
    parser.add_argument(
        'interface',
        nargs='?',
        default='enp11s0',
        help='Network interface to capture from (default: enp11s0)'
    )
    parser.add_argument(
        '--min-packets',
        type=int,
        default=3,
        help='Minimum packets per flow to analyze (default: 3)'
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
    
    logs_dir = script_dir / 'logs'
    logs_dir.mkdir(exist_ok=True)
    
    # Setup logging
    logger = setup_logging(logs_dir / 'detections.log')
    
    # Check for root privileges
    if os.geteuid() != 0:
        print(f"{Colors.RED}Error: Root privileges required for live capture.{Colors.RESET}")
        print(f"Run with: sudo {sys.executable} {' '.join(sys.argv)}")
        sys.exit(1)
    
    # Load model
    print(f"{Colors.YELLOW}Loading trained model...{Colors.RESET}")
    try:
        model, scaler, feature_names, label_encoder = load_model(models_dir)
        print(f"{Colors.GREEN}✓ Model loaded successfully{Colors.RESET}")
        print(f"  Classes: {list(label_encoder.classes_)}")
    except Exception as e:
        print(f"{Colors.RED}Error loading model: {e}{Colors.RESET}")
        print("Make sure you've trained the model first: python src/train_model.py")
        sys.exit(1)
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print_banner()
    print(f"{Colors.BLUE}Interface:{Colors.RESET} {args.interface}")
    print(f"{Colors.BLUE}Min packets:{Colors.RESET} {args.min_packets}")
    print(f"{Colors.BLUE}Logging to:{Colors.RESET} {logs_dir / 'detections.log'}")
    print(f"\n{Colors.YELLOW}Press Ctrl+C to stop{Colors.RESET}\n")
    print("="*65)
    print()
    
    # Statistics
    stats = {
        'total_flows': 0,
        'benign_count': 0,
        'attack_count': 0,
        'start_time': datetime.now()
    }
    
    try:
        # Create live streamer
        streamer = NFStreamer(
            source=args.interface,
            statistical_analysis=True,
            idle_timeout=15,
            active_timeout=60
        )
        
        for flow in streamer:
            if not running:
                break
            
            # Skip flows with too few packets
            if flow.bidirectional_packets < args.min_packets:
                continue
            
            # Extract features
            features = extract_flow_features(flow)
            
            # Create feature array in correct order
            feature_array = np.array([[features[f] for f in feature_names]])
            
            # Handle NaN/Inf
            if np.any(np.isnan(feature_array)) or np.any(np.isinf(feature_array)):
                continue
            
            # Scale features
            feature_array_scaled = scaler.transform(feature_array)
            
            # Predict
            prediction = model.predict(feature_array_scaled)[0]
            proba = model.predict_proba(feature_array_scaled)[0]
            confidence = proba.max() * 100
            
            # Get label
            label = label_encoder.classes_[prediction]
            is_attack = label != 'BENIGN'
            
            # Update stats
            stats['total_flows'] += 1
            if is_attack:
                stats['attack_count'] += 1
            else:
                stats['benign_count'] += 1
            
            # Print detection
            print_detection(flow, label, confidence, is_attack)
            
            # Log detection
            log_msg = f"Flow: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} | " \
                      f"Prediction: {label} ({confidence:.1f}%) | " \
                      f"Packets: {flow.bidirectional_packets}"
            logger.info(log_msg)
    
    except Exception as e:
        print(f"{Colors.RED}Error during capture: {e}{Colors.RESET}")
    
    # Print final statistics
    elapsed = datetime.now() - stats['start_time']
    
    print("\n" + "="*65)
    print(f"{Colors.BOLD}SESSION STATISTICS{Colors.RESET}")
    print("="*65)
    print(f"Duration:       {elapsed}")
    print(f"Total flows:    {stats['total_flows']}")
    print(f"Benign flows:   {Colors.GREEN}{stats['benign_count']}{Colors.RESET}")
    print(f"Attack flows:   {Colors.RED}{stats['attack_count']}{Colors.RESET}")
    
    if stats['total_flows'] > 0:
        attack_rate = stats['attack_count'] / stats['total_flows'] * 100
        print(f"Attack rate:    {attack_rate:.1f}%")
    
    print("="*65)
    print(f"\n{Colors.GREEN}Session ended.{Colors.RESET}\n")


if __name__ == '__main__':
    main()
