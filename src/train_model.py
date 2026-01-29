#!/usr/bin/env python3
"""
ThreatGuard-AI Model Training Script v2

Improved model with better handling of class imbalance and
attack pattern detection.

Author: ThreatGuard-AI Team
"""

import os
import sys
import argparse
import logging
import warnings
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

warnings.filterwarnings('ignore')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/training.log')
    ]
)
logger = logging.getLogger(__name__)

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


def load_and_balance_data(file_path: Path) -> tuple:
    """
    Load data and balance classes by undersampling majority classes.
    Dynamically handles multiple attack types (UDP, SYN, etc.)
    """
    logger.info(f"Loading data from {file_path}")
    
    df = pd.read_csv(file_path)
    logger.info(f"Loaded {len(df):,} samples")
    
    # Check benign count
    benign_count = len(df[df['label'] == 'BENIGN'])
    if benign_count == 0:
        logger.warning("No BENIGN samples found! Balancing might fail.")
        benign_count = 1000 # Fallback to avoid errors

    logger.info(f"BENIGN samples: {benign_count:,}")
    
    # Target count for attack classes (e.g., 5x benign)
    target_count = benign_count * 5
    
    balanced_dfs = []
    labels = df['label'].unique()
    
    for label in labels:
        subset = df[df['label'] == label]
        count = len(subset)
        
        if label == 'BENIGN':
            balanced_dfs.append(subset)
        else:
            # Undersample attack classes
            if count > target_count:
                subset = subset.sample(n=target_count, random_state=42)
                logger.info(f"  {label}: Resampled {count:,} -> {target_count:,}")
            else:
                logger.info(f"  {label}: Kept all {count:,}")
            balanced_dfs.append(subset)
    
    # Combine
    df_balanced = pd.concat(balanced_dfs, ignore_index=True)
    df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Extract features and labels
    X = df_balanced[FEATURE_NAMES].copy()
    y = df_balanced['label'].copy()
    
    # Handle NaN/Inf
    X = X.replace([np.inf, -np.inf], np.nan)
    mask = ~X.isna().any(axis=1)
    X = X[mask]
    y = y[mask]
    
    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    # Log class mapping
    mapping = dict(zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_)))
    logger.info(f"Class Mapping: {mapping}")
    
    return X, y_encoded, label_encoder


def train_model(X_train, y_train):
    """Train Random Forest with better parameters for balanced detection."""
    logger.info("Training Random Forest classifier...")
    
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1,
        class_weight={0: 1, 1: 1}  # Equal weight now that data is balanced
    )
    
    model.fit(X_train, y_train)
    return model


def evaluate_model(model, X_test, y_test, label_encoder):
    """Evaluate model and return metrics."""
    y_pred = model.predict(X_test)
    
    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision_weighted': precision_score(y_test, y_pred, average='weighted'),
        'recall_weighted': recall_score(y_test, y_pred, average='weighted'),
        'f1_weighted': f1_score(y_test, y_pred, average='weighted')
    }
    
    return metrics, y_pred


def plot_confusion_matrix(y_true, y_pred, classes, output_path: Path):
    """Create confusion matrix visualization."""
    cm = confusion_matrix(y_true, y_pred)
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(
        cm,
        annot=True,
        fmt='d',
        cmap='Blues',
        xticklabels=classes,
        yticklabels=classes,
        annot_kws={'size': 14}
    )
    plt.title('Confusion Matrix (Balanced Model)', fontsize=16, fontweight='bold')
    plt.ylabel('Actual', fontsize=12)
    plt.xlabel('Predicted', fontsize=12)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()


def main():
    """Main training function with balanced dataset."""
    
    parser = argparse.ArgumentParser(description='Train DDoS detection model v2')
    parser.add_argument('--input', type=str, default='data/processed/features.csv')
    args = parser.parse_args()
    
    script_dir = Path(__file__).parent.parent
    input_path = Path(args.input)
    if not input_path.is_absolute():
        input_path = script_dir / input_path
    
    models_dir = script_dir / 'models'
    logs_dir = script_dir / 'logs'
    models_dir.mkdir(exist_ok=True)
    logs_dir.mkdir(exist_ok=True)
    
    print("\n" + "="*60)
    print("   THREATGUARD-AI MODEL TRAINING v2 (BALANCED)")
    print("="*60 + "\n")
    
    # Load and balance data
    X, y, label_encoder = load_and_balance_data(input_path)
    
    print("📊 Balanced Class Distribution:")
    for i, class_name in enumerate(label_encoder.classes_):
        count = (y == i).sum()
        percentage = count / len(y) * 100
        print(f"  {class_name}: {count:,} ({percentage:.1f}%)")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\n📈 Training set: {len(X_train):,} samples")
    print(f"📈 Test set: {len(X_test):,} samples")
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train
    print("\n🔧 Training Random Forest classifier...")
    start_time = datetime.now()
    model = train_model(X_train_scaled, y_train)
    print(f"✓ Training completed in {datetime.now() - start_time}")
    
    # Cross-validation
    print("\n🔄 Running cross-validation...")
    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5)
    print(f"✓ CV Scores: {cv_scores.mean():.4f} (±{cv_scores.std()*2:.4f})")
    
    # Evaluate
    print("\n📊 Evaluating model...")
    metrics, y_pred = evaluate_model(model, X_test_scaled, y_test, label_encoder)
    
    print("\n" + "="*60)
    print("RESULTS")
    print("="*60)
    
    print(f"\n✅ Overall Accuracy: {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print(f"   Precision: {metrics['precision_weighted']:.4f}")
    print(f"   Recall:    {metrics['recall_weighted']:.4f}")
    print(f"   F1-Score:  {metrics['f1_weighted']:.4f}")
    
    # Per-class metrics
    print("\n📊 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
    
    # Confusion matrix
    plot_confusion_matrix(y_test, y_pred, label_encoder.classes_, 
                         logs_dir / 'confusion_matrix.png')
    
    # Save
    print("\n💾 Saving model...")
    joblib.dump(model, models_dir / 'ddos_model.pkl')
    joblib.dump(scaler, models_dir / 'scaler.pkl')
    joblib.dump(FEATURE_NAMES, models_dir / 'feature_names.pkl')
    joblib.dump(label_encoder, models_dir / 'label_encoder.pkl')
    
    print(f"   ✓ Model saved to models/")
    print("\n" + "="*60)
    print("✅ MODEL TRAINING COMPLETE!")
    print("="*60 + "\n")


if __name__ == '__main__':
    main()
