#!/usr/bin/env python3
"""
ThreatGuard-AI Feature Extraction Script

Extracts network flow features from PCAP files using NFStream.
Labels flows based on timestamp (BENIGN or UDP attack).

This script uses the SAME feature extraction function that will be used
in live capture, ensuring consistency between training and deployment.

Author: ThreatGuard-AI Team
"""

import os
import sys
import argparse
import logging
from pathlib import Path
from datetime import datetime, time
from typing import Dict, Optional, List, Tuple

import pandas as pd
import numpy as np
from tqdm import tqdm
from nfstream import NFStreamer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/feature_extraction.log')
    ]
)
logger = logging.getLogger(__name__)

# =============================================================================
# FEATURE LIST - MUST BE IDENTICAL IN TRAINING AND LIVE CAPTURE
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
    
    CRITICAL: This function MUST be identical for training and live capture.
    Any changes here must be reflected in capture_live.py as well.
    
    Args:
        flow: NFStream flow object
        
    Returns:
        Dictionary of extracted features
    """
    # Avoid division by zero - use minimum duration of 1ms
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


def label_flow_by_timestamp(timestamp_ms: int) -> Optional[str]:
    """
    Label a flow based on its timestamp.
    
    Supports:
    - CIC-DDoS2019 Day 1 (Jan 12): SYN Flood (10:31 - 11:15)
    - CIC-DDoS2019 Day 2 (Mar 11): UDP Flood (> 18:01)
    
    Args:
        timestamp_ms: Flow start timestamp in milliseconds since epoch
        
    Returns:
        'BENIGN', 'UDP', 'SYN', or None if label cannot be determined
    """
    try:
        dt = datetime.fromtimestamp(timestamp_ms / 1000)
        flow_time = dt.time()
        
        # Day 1: January 12th, 2019 (SYN Flood)
        if dt.month == 1 and dt.day == 12:
            if time(10, 31) <= flow_time <= time(11, 15):
                return 'SYN'
            elif flow_time < time(10, 31):
                return 'BENIGN'
            else:
                return 'BENIGN' # Rest of the day is likely benign (or other attacks we ignore for now)
                
        # Day 2: March 11th, 2019 (UDP Flood)
        elif dt.month == 3 and dt.day == 11:
            if flow_time >= time(18, 1):
                return 'UDP'
            else:
                return 'BENIGN'
                
        # Handle other dates (e.g. custom captures without forced labels)
        # If it's a known date, handle it. If not, default to None or BENIGN?
        # Ideally custom files use --force-label.
        return None
            
    except Exception as e:
        logger.warning(f"Could not parse timestamp {timestamp_ms}: {e}")
        return None


def get_pcap_files(pcap_dir: Path) -> List[Path]:
    """
    Get sorted list of PCAP files from directory.
    
    Args:
        pcap_dir: Path to directory containing PCAP files
        
    Returns:
        Sorted list of PCAP file paths
    """
    pcap_files = []
    
    for f in pcap_dir.iterdir():
        if f.is_file() and (f.suffix == '.pcap' or f.name.startswith('SAT-03-11') or f.name.startswith('my_traffic')):
            pcap_files.append(f)
    
    # Sort files numerically (handle _0, _01, _02, etc.)
    def sort_key(p: Path) -> Tuple[int, str]:
        name = p.name
        # Default sort by name for custom files
        return (0, name)
    
    pcap_files.sort(key=sort_key)
    return pcap_files


def process_pcap_file(pcap_path: Path, min_packets: int = 2, args=None) -> List[Dict]:
    """
    Process a single PCAP file and extract labeled flow features.
    
    Args:
        pcap_path: Path to PCAP file
        min_packets: Minimum number of packets for a flow to be considered
        
    Returns:
        List of feature dictionaries with labels
    """
    flows_data = []
    
    try:
        # Create NFStreamer with statistical analysis
        streamer = NFStreamer(
            source=str(pcap_path),
            statistical_analysis=True,
            idle_timeout=30,
            active_timeout=120
        )
        
        for flow in streamer:
            # Skip flows with too few packets
            if flow.bidirectional_packets < min_packets:
                continue
            
            # Get label based on timestamp or forced label
            if args.force_label:
                label = args.force_label
            else:
                label = label_flow_by_timestamp(flow.bidirectional_first_seen_ms)
            
            if label is None:
                continue
            
            # Extract features
            features = extract_flow_features(flow)
            features['label'] = label
            
            # Add metadata for debugging
            features['src_ip'] = flow.src_ip
            features['dst_ip'] = flow.dst_ip
            features['src_port'] = flow.src_port
            features['dst_port'] = flow.dst_port
            features['protocol'] = flow.protocol
            features['timestamp'] = flow.bidirectional_first_seen_ms
            
            flows_data.append(features)
            
    except Exception as e:
        logger.error(f"Error processing {pcap_path.name}: {e}")
    
    return flows_data


def validate_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean and validate extracted features.
    
    - Remove NaN values
    - Remove infinity values
    - Clip extreme outliers
    
    Args:
        df: DataFrame with extracted features
        
    Returns:
        Cleaned DataFrame
    """
    logger.info("Validating and cleaning features...")
    
    initial_count = len(df)
    
    # Replace infinities with NaN, then drop
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Drop rows with NaN in feature columns
    df = df.dropna(subset=FEATURE_NAMES)
    
    # Clip extreme values (99.9th percentile)
    for col in FEATURE_NAMES:
        upper = df[col].quantile(0.999)
        df[col] = df[col].clip(upper=upper)
    
    final_count = len(df)
    removed = initial_count - final_count
    
    if removed > 0:
        logger.info(f"Removed {removed} invalid rows ({removed/initial_count*100:.2f}%)")
    
    return df


def print_statistics(df: pd.DataFrame) -> None:
    """Print detailed statistics about extracted features."""
    
    print("\n" + "="*60)
    print("FEATURE EXTRACTION STATISTICS")
    print("="*60)
    
    # Label distribution
    print("\n📊 Label Distribution:")
    label_counts = df['label'].value_counts()
    for label, count in label_counts.items():
        percentage = count / len(df) * 100
        print(f"  {label}: {count:,} flows ({percentage:.1f}%)")
    
    print(f"\n  Total: {len(df):,} flows")
    
    # Feature ranges
    print("\n📈 Feature Value Ranges:")
    print("-"*60)
    print(f"{'Feature':<25} {'Min':>12} {'Max':>12} {'Mean':>12}")
    print("-"*60)
    
    for feature in FEATURE_NAMES:
        min_val = df[feature].min()
        max_val = df[feature].max()
        mean_val = df[feature].mean()
        print(f"{feature:<25} {min_val:>12.2f} {max_val:>12.2f} {mean_val:>12.2f}")
    
    print("-"*60)
    
    # Protocol distribution
    if 'protocol' in df.columns:
        print("\n🔌 Protocol Distribution:")
        proto_counts = df['protocol'].value_counts().head(5)
        for proto, count in proto_counts.items():
            proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, f'Proto_{proto}')
            print(f"  {proto_name}: {count:,}")


def main():
    """Main function to extract features from PCAP files."""
    
    parser = argparse.ArgumentParser(
        description='Extract network flow features from PCAP files for DDoS detection'
    )
    parser.add_argument(
        '--force-label',
        type=str,
        default=None,
        help='Force a specific label for all flows (e.g., BENIGN)'
    )
    parser.add_argument(
        '--pcap-dir',
        type=str,
        default='data/PCAP-03-11',
        help='Directory containing PCAP files (default: data/PCAP-03-11)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='data/processed/features.csv',
        help='Output CSV file path (default: data/processed/features.csv)'
    )
    parser.add_argument(
        '--min-packets',
        type=int,
        default=2,
        help='Minimum packets per flow (default: 2)'
    )
    parser.add_argument(
        '--max-files',
        type=int,
        default=None,
        help='Maximum number of PCAP files to process (default: all)'
    )
    
    args = parser.parse_args()
    
    # Resolve paths
    script_dir = Path(__file__).parent.parent
    pcap_dir = Path(args.pcap_dir)
    if not pcap_dir.is_absolute():
        pcap_dir = script_dir / pcap_dir
    
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = script_dir / output_path
    
    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Check PCAP directory exists
    if not pcap_dir.exists():
        logger.error(f"PCAP directory not found: {pcap_dir}")
        sys.exit(1)
    
    # Get PCAP files
    pcap_files = get_pcap_files(pcap_dir)
    
    if not pcap_files:
        logger.error(f"No PCAP files found in {pcap_dir}")
        sys.exit(1)
    
    if args.max_files:
        pcap_files = pcap_files[:args.max_files]
    
    logger.info(f"Found {len(pcap_files)} PCAP files to process")
    
    # Process all PCAP files
    print("\n🔄 Processing PCAP files...")
    start_time = datetime.now()
    
    all_flows = []
    
    for pcap_path in tqdm(pcap_files, desc="Processing PCAPs", unit="file"):
        flows = process_pcap_file(pcap_path, args.min_packets, args)
        all_flows.extend(flows)
        
        if len(all_flows) % 10000 == 0:
            logger.info(f"Processed {len(all_flows):,} flows so far...")
    
    # Convert to DataFrame
    df = pd.DataFrame(all_flows)
    
    if df.empty:
        logger.error("No flows extracted! Check PCAP files.")
        sys.exit(1)
    
    logger.info(f"Extracted {len(df):,} total flows")
    
    # Validate and clean features
    df = validate_features(df)
    
    # Save to CSV
    # Save only feature columns + label for training
    training_columns = FEATURE_NAMES + ['label']
    df_training = df[training_columns]
    df_training.to_csv(output_path, index=False)
    
    logger.info(f"Saved features to {output_path}")
    
    # Save full data with metadata for analysis
    full_output = output_path.parent / 'features_full.csv'
    df.to_csv(full_output, index=False)
    logger.info(f"Saved full data to {full_output}")
    
    # Calculate processing time
    elapsed = datetime.now() - start_time
    
    # Print statistics
    print_statistics(df)
    
    print(f"\n⏱️  Processing time: {elapsed}")
    print(f"📁 Output saved to: {output_path}")
    print("\n✅ Feature extraction complete!")


if __name__ == '__main__':
    main()
