# Software Design Specification (SDS)
## ThreatGuard-AI: Real-Time DDoS Detection System

**Document Version:** 1.0  
**Date:** January 30, 2026  
**Project:** ThreatGuard-AI  
**Author:** ThreatGuard-AI Team

---

# Table of Contents

1. [Introduction](#1-introduction)
2. [Design Considerations](#2-design-considerations)
3. [System Architecture](#3-system-architecture)
4. [Detailed System Design](#4-detailed-system-design)
5. [Database Design](#5-database-design)
6. [Application Design](#6-application-design)
7. [References](#7-references)
8. [Appendices](#8-appendices)

---

# 1. Introduction

## 1.1 Purpose of Document

This Software Design Specification (SDS) document provides a comprehensive technical blueprint for the ThreatGuard-AI real-time DDoS detection system. The document translates the requirements defined in the SRS into a detailed design that developers can directly implement.

**Design Methodology:** Object-Oriented Design (OOD) with modular architecture

**This document serves to:**
- Define the system architecture and component interactions
- Specify detailed class designs, data structures, and algorithms
- Document database schema and data flow
- Provide GUI mockups and sequence diagrams for implementation
- Establish design patterns and coding conventions

## 1.2 Intended Audience

| Audience | Purpose |
|----------|---------|
| **Software Developers** | Primary reference for implementing system components |
| **System Architects** | Review and validate architectural decisions |
| **QA Engineers** | Understand system structure for test planning |
| **Database Administrators** | Reference for data model implementation |
| **Project Supervisor** | Evaluate technical design quality |
| **Maintenance Engineers** | Future reference for system modifications |

## 1.3 Document Convention

| Element | Convention |
|---------|------------|
| **Body Text** | Arial, 11pt |
| **Headings Level 1** | Arial Bold, 16pt |
| **Headings Level 2** | Arial Bold, 14pt |
| **Headings Level 3** | Arial Bold, 12pt |
| **Code/Technical Terms** | Consolas, 10pt, monospace |
| **Table Headers** | Arial Bold, 11pt, shaded |
| **Diagrams** | Mermaid/UML notation |

## 1.4 Project Overview

ThreatGuard-AI is a machine learning-based network security system that detects DDoS attacks in real-time. The system uses Random Forest classification on network flow features extracted via NFStream.

**Core Components:**
1. **Feature Extraction Engine** - Processes PCAP files using NFStream to extract 12 flow-based features
2. **ML Training Pipeline** - Trains Random Forest classifier with class balancing
3. **Live Detection Engine** - Real-time network capture and classification
4. **Web Dashboard** - Flask-based monitoring interface with REST API

**Technology Stack:**
- Python 3.8+, Flask, NFStream, scikit-learn, pandas, numpy
- HTML5/CSS3/JavaScript for frontend
- Pickle (.pkl) for model serialization

## 1.5 Scope

### In Scope (Design)
- Modular Python architecture with 4 main components
- REST API design for dashboard communication
- Real-time flow processing pipeline
- Model serialization and loading mechanisms
- Responsive web dashboard design

### Out of Scope (Design)
- Cloud deployment architecture
- User authentication system
- Database persistence (file-based storage only)
- Mobile application interfaces

---

# 2. Design Considerations

## 2.1 Assumptions and Dependencies

### Design Assumptions

| ID | Assumption | Impact |
|----|------------|--------|
| DA-01 | Feature extraction logic must be identical in training and detection modules | Requires shared code or strict synchronization |
| DA-02 | Model artifacts are loaded once at startup | Memory-resident inference for performance |
| DA-03 | Single network interface monitoring per instance | Simplifies capture thread design |
| DA-04 | Dashboard polling (not WebSocket) acceptable for 1s updates | Reduces implementation complexity |

### Design Dependencies

| Dependency | Resolution Required Before |
|------------|---------------------------|
| NFStream flow object structure | Feature extraction implementation |
| scikit-learn model serialization format | Model persistence design |
| Flask threading model | Background capture integration |

## 2.2 Risks and Volatile Areas

### Design Risks

| Risk | Probability | Impact | Mitigation Strategy |
|------|-------------|--------|---------------------|
| NFStream API changes | Medium | High | Version pinning in requirements.txt |
| Feature drift between training/detection | High | Critical | Centralized FEATURE_NAMES constant |
| Memory leaks in long-running capture | Medium | Medium | Flow count limits, periodic restart capability |
| Model accuracy degradation | Low | High | Logging for monitoring, retraining workflow |

### Volatile Areas

| Area | Likely Change | Design Response |
|------|---------------|-----------------|
| Attack types | New DDoS variants | Extensible label encoding, model retraining pipeline |
| Feature set | Additional flow metrics | FEATURE_NAMES list centralization |
| Dashboard metrics | New statistics | Extensible status dictionary |
| Detection thresholds | Tuning requirements | Configurable via command-line arguments |

---

# 3. System Architecture

## 3.1 System Level Architecture

### System Decomposition

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ThreatGuard-AI System                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐       │
│  │   Feature        │  │   Model          │  │   Live           │       │
│  │   Extraction     │  │   Training       │  │   Detection      │       │
│  │   Module         │  │   Module         │  │   Module         │       │
│  │                  │  │                  │  │                  │       │
│  │  extract_        │  │  train_          │  │  capture_        │       │
│  │  features.py     │  │  model.py        │  │  live.py         │       │
│  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘       │
│           │                     │                     │                  │
│           ▼                     ▼                     ▼                  │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                      Shared Components                            │   │
│  │  • FEATURE_NAMES constant    • extract_flow_features() function  │   │
│  │  • Model artifacts (.pkl)    • Logging configuration             │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                      Dashboard Module                             │   │
│  │                         backend.py                                │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐               │   │
│  │  │ Flask App   │  │ Capture     │  │ REST API    │               │   │
│  │  │ Server      │  │ Thread      │  │ Endpoints   │               │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘               │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           «component»                                    │
│                        ThreatGuard-AI                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────┐         ┌─────────────────────┐                │
│  │    «component»      │         │    «component»      │                │
│  │  FeatureExtractor   │────────▶│   ModelTrainer      │                │
│  │                     │ CSV     │                     │                │
│  │  - process_pcap()   │ Output  │  - train_model()    │                │
│  │  - extract_flow()   │         │  - evaluate()       │                │
│  │  - validate()       │         │  - save_model()     │                │
│  └─────────────────────┘         └──────────┬──────────┘                │
│                                              │ .pkl                      │
│                                              ▼                           │
│  ┌─────────────────────┐         ┌─────────────────────┐                │
│  │    «component»      │◀────────│    «component»      │                │
│  │   WebDashboard      │  Model  │   LiveDetector      │                │
│  │                     │  Load   │                     │                │
│  │  - serve_html()     │         │  - capture_flow()   │                │
│  │  - api_status()     │◀────────│  - classify()       │                │
│  │  - update_ui()      │ Status  │  - log_attack()     │                │
│  └─────────────────────┘         └─────────────────────┘                │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### External Interfaces

| Interface | Type | Description |
|-----------|------|-------------|
| Network Interface | Hardware | Raw packet capture via libpcap/NFStream |
| File System | Software | PCAP input, CSV output, .pkl model storage |
| HTTP/REST | Network | Dashboard API on port 5000 |
| Web Browser | User | Dashboard HTML rendering |

### Global Design Strategies

**Error Handling:**
- Try-catch blocks around all I/O operations
- Graceful degradation (continue on non-critical errors)
- Signal handlers for clean shutdown (SIGINT, SIGTERM)

**Logging:**
- Centralized logging configuration
- Separate log files: training.log, detections.log, feature_extraction.log
- Console + file output with timestamps

**Configuration:**
- Command-line arguments with sensible defaults
- Path resolution relative to script location
- No hardcoded absolute paths

## 3.2 Software Architecture

### Layered Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        PRESENTATION LAYER                                │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    dashboard.html                                │    │
│  │  • HTML5 structure    • CSS3 styling    • JavaScript updates    │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                   │                                      │
│                                   │ HTTP GET/JSON                        │
│                                   ▼                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                        APPLICATION LAYER                                 │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                       Flask Application                          │    │
│  │  Routes: /  →  dashboard()                                       │    │
│  │          /api/status  →  get_status()                            │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                   │                                      │
│                                   │ Function calls                       │
│                                   ▼                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                        BUSINESS LOGIC LAYER                              │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐             │
│  │ Feature        │  │ Classification │  │ Status         │             │
│  │ Extraction     │  │ Engine         │  │ Management     │             │
│  │                │  │                │  │                │             │
│  │ extract_flow_  │  │ model.predict()│  │ status dict    │             │
│  │ features()     │  │ scaler.trans() │  │ attack_logs    │             │
│  └────────────────┘  └────────────────┘  └────────────────┘             │
│                                   │                                      │
│                                   │ Library calls                        │
│                                   ▼                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                        DATA ACCESS LAYER                                 │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐             │
│  │ NFStreamer     │  │ joblib         │  │ pandas         │             │
│  │ (capture)      │  │ (model I/O)    │  │ (CSV I/O)      │             │
│  └────────────────┘  └────────────────┘  └────────────────┘             │
│                                   │                                      │
│                                   │ System calls                         │
│                                   ▼                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                        INFRASTRUCTURE LAYER                              │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐             │
│  │ Network        │  │ File System    │  │ Operating      │             │
│  │ Interface      │  │                │  │ System         │             │
│  └────────────────┘  └────────────────┘  └────────────────┘             │
└─────────────────────────────────────────────────────────────────────────┘
```

## 3.3 Design Strategy

### Future Extension Strategy

| Extension | Design Provision |
|-----------|------------------|
| New attack types | Label encoder handles dynamic classes; retrain with new labels |
| Additional features | FEATURE_NAMES list is centralized; add new metrics easily |
| Multiple interfaces | Spawn additional capture threads with interface parameter |
| Alert notifications | Add notification service call in attack detection block |

### System Reuse Strategy

| Reusable Component | Reuse Approach |
|--------------------|----------------|
| `extract_flow_features()` | Shared function imported by all modules |
| FEATURE_NAMES | Single constant definition |
| Model loading | `load_model()` function in backend.py |

### Data Management Strategy

| Aspect | Strategy |
|--------|----------|
| Storage | File-based (.pkl for models, .csv for features, .log for logs) |
| Persistence | Models persisted via joblib; logs appended to files |
| Distribution | Single-node design; all data local |

### Concurrency Strategy

| Component | Concurrency Model |
|-----------|-------------------|
| Network Capture | Background daemon thread |
| Flask Server | Main thread with Werkzeug |
| Model Inference | Synchronous within capture thread |
| Status Updates | Thread-safe global dictionary |

---

# 4. Detailed System Design

## Design Class Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Class Diagram                               │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────┐
│      «module» backend.py        │
├─────────────────────────────────┤
│ - app: Flask                    │
│ - status: Dict[str, Any]        │
│ - model: RandomForestClassifier │
│ - scaler: StandardScaler        │
│ - label_encoder: LabelEncoder   │
│ - running: bool                 │
│ - capture_thread: Thread        │
│ - FEATURE_NAMES: List[str]      │
├─────────────────────────────────┤
│ + extract_flow_features(flow)   │
│ + load_model(models_dir)        │
│ + capture_thread_func(iface)    │
│ + dashboard() → HTML            │
│ + get_status() → JSON           │
│ + signal_handler(sig, frame)    │
│ + main()                        │
└─────────────────────────────────┘
              │
              │ uses
              ▼
┌─────────────────────────────────┐       ┌─────────────────────────────────┐
│  «module» extract_features.py   │       │   «module» train_model.py       │
├─────────────────────────────────┤       ├─────────────────────────────────┤
│ - FEATURE_NAMES: List[str]      │       │ - FEATURE_NAMES: List[str]      │
│ - logger: Logger                │       │ - logger: Logger                │
├─────────────────────────────────┤       ├─────────────────────────────────┤
│ + extract_flow_features(flow)   │──────▶│ + load_and_balance_data(path)   │
│ + label_flow_by_timestamp(ts)   │ CSV   │ + train_model(X, y)             │
│ + get_pcap_files(dir)           │       │ + evaluate_model(model, X, y)   │
│ + process_pcap_file(path)       │       │ + plot_confusion_matrix(...)    │
│ + validate_features(df)         │       │ + main()                        │
│ + print_statistics(df)          │       │                                 │
│ + main()                        │       │                                 │
└─────────────────────────────────┘       └─────────────────────────────────┘
```

## Class Descriptions

### backend.py Module

| Attribute/Method | Type | Description |
|------------------|------|-------------|
| `app` | Flask | Flask application instance |
| `status` | Dict | Global status dictionary with detection state |
| `model` | RandomForestClassifier | Loaded ML model for classification |
| `scaler` | StandardScaler | Feature scaling transformer |
| `extract_flow_features(flow)` | Function | Extracts 12 features from NFStream flow object |
| `load_model(models_dir)` | Function | Loads all model artifacts from directory |
| `capture_thread_func(interface)` | Function | Background thread for network capture and detection |
| `dashboard()` | Route | Serves HTML dashboard page |
| `get_status()` | Route | Returns JSON status for API |

### Status Dictionary Structure

```python
status = {
    'current_status': str,      # 'INITIALIZING' | 'SAFE' | 'UNDER_ATTACK' | 'ERROR'
    'attack_type': str | None,  # 'UDP' | 'SYN' | None
    'total_flows': int,         # Count of analyzed flows
    'attack_count': int,        # Count of attack flows
    'benign_count': int,        # Count of benign flows
    'last_attack_time': str,    # ISO timestamp of last attack
    'uptime_seconds': int,      # System uptime
    'consecutive_benign': int,  # Counter for safe status transition
    'is_capturing': bool,       # Capture thread status
    'interface': str,           # Network interface name
    'attack_logs': List[Dict]   # Recent attack log entries
}
```

---

# 5. Database Design

## 5.1 ER Diagram

ThreatGuard-AI uses file-based storage rather than a traditional database. The following entities represent the data structures:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           ER Diagram                                     │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
│   NetworkFlow   │          │   TrainingData  │          │  ModelArtifact  │
├─────────────────┤          ├─────────────────┤          ├─────────────────┤
│ PK flow_id      │          │ PK sample_id    │          │ PK artifact_id  │
│    src_ip       │──────────│    features[]   │──────────│    model_blob   │
│    dst_ip       │  extracts│    label        │  trains  │    scaler_blob  │
│    src_port     │          │    timestamp    │          │    encoder_blob │
│    dst_port     │          │                 │          │    created_at   │
│    protocol     │          │                 │          │                 │
│    timestamp    │          │                 │          │                 │
│    features[]   │          │                 │          │                 │
│    prediction   │          │                 │          │                 │
└─────────────────┘          └─────────────────┘          └─────────────────┘
        │                                                          │
        │ generates                                                │
        ▼                                                          │
┌─────────────────┐                                                │
│   AttackLog     │                                                │
├─────────────────┤                                       uses for │
│ PK log_id       │                                       inference│
│    timestamp    │◀───────────────────────────────────────────────┘
│    attack_type  │
│    src_addr     │
│    dst_addr     │
│    packet_count │
└─────────────────┘
```

## 5.2 Data Dictionary

### **NetworkFlow (In-Memory)**

| Aspect | Details |
|--------|---------|
| Name | NetworkFlow |
| Alias | Flow, Packet Flow |
| Where-used/how-used | Created by NFStreamer during capture; used by classification engine for prediction |
| Content description | NetworkFlow = flow_id + src_ip + dst_ip + src_port + dst_port + protocol + timestamp + features{12} + prediction |

**Table Structure:**

| Column Name | Description | Type | Length | Nullable | Default | Key |
|-------------|-------------|------|--------|----------|---------|-----|
| flow_id | Unique flow identifier | INTEGER | - | No | Auto | PK |
| src_ip | Source IP address | VARCHAR | 45 | No | - | - |
| dst_ip | Destination IP address | VARCHAR | 45 | No | - | - |
| src_port | Source port number | INTEGER | - | No | - | - |
| dst_port | Destination port number | INTEGER | - | No | - | - |
| protocol | IP protocol number (6=TCP, 17=UDP) | INTEGER | - | No | - | - |
| timestamp | Flow start time (ms since epoch) | BIGINT | - | No | - | - |
| flow_duration_ms | Duration in milliseconds | FLOAT | - | No | 0 | - |
| total_fwd_packets | Forward packet count | INTEGER | - | No | 0 | - |
| total_bwd_packets | Backward packet count | INTEGER | - | No | 0 | - |
| flow_bytes_per_sec | Throughput in bytes/second | FLOAT | - | No | 0 | - |
| flow_packets_per_sec | Packet rate per second | FLOAT | - | No | 0 | - |
| fwd_packet_length_mean | Mean forward packet size | FLOAT | - | No | 0 | - |
| bwd_packet_length_mean | Mean backward packet size | FLOAT | - | No | 0 | - |
| flow_iat_mean | Mean inter-arrival time (ms) | FLOAT | - | No | 0 | - |
| fwd_packet_length_max | Max forward packet size | FLOAT | - | No | 0 | - |
| bwd_packet_length_max | Max backward packet size | FLOAT | - | No | 0 | - |
| fwd_iat_mean | Forward IAT mean (ms) | FLOAT | - | No | 0 | - |
| bwd_iat_mean | Backward IAT mean (ms) | FLOAT | - | No | 0 | - |
| prediction | Classification result | VARCHAR | 20 | Yes | NULL | - |

---

### **TrainingData (features.csv)**

| Aspect | Details |
|--------|---------|
| Name | TrainingData |
| Alias | Feature CSV, Training Dataset |
| Where-used/how-used | Output of extract_features.py; input to train_model.py |
| Content description | TrainingData = {feature_row}n where feature_row = features{12} + label |

**Table Structure:**

| Column Name | Description | Type | Length | Nullable | Default | Key |
|-------------|-------------|------|--------|----------|---------|-----|
| flow_duration_ms | Duration in milliseconds | FLOAT | - | No | - | - |
| total_fwd_packets | Forward packet count | INTEGER | - | No | - | - |
| total_bwd_packets | Backward packet count | INTEGER | - | No | - | - |
| flow_bytes_per_sec | Throughput bytes/sec | FLOAT | - | No | - | - |
| flow_packets_per_sec | Packet rate/sec | FLOAT | - | No | - | - |
| fwd_packet_length_mean | Mean fwd packet size | FLOAT | - | No | - | - |
| bwd_packet_length_mean | Mean bwd packet size | FLOAT | - | No | - | - |
| flow_iat_mean | Mean IAT (ms) | FLOAT | - | No | - | - |
| fwd_packet_length_max | Max fwd packet size | FLOAT | - | No | - | - |
| bwd_packet_length_max | Max bwd packet size | FLOAT | - | No | - | - |
| fwd_iat_mean | Fwd IAT mean (ms) | FLOAT | - | No | - | - |
| bwd_iat_mean | Bwd IAT mean (ms) | FLOAT | - | No | - | - |
| label | Classification label | VARCHAR | 20 | No | - | - |

---

### **AttackLog (In-Memory/Log File)**

| Aspect | Details |
|--------|---------|
| Name | AttackLog |
| Alias | Detection Log |
| Where-used/how-used | Created when attack detected; displayed in dashboard; written to detections.log |
| Content description | AttackLog = time + type + src + dst + packets |

**Table Structure:**

| Column Name | Description | Type | Length | Nullable | Default | Key |
|-------------|-------------|------|--------|----------|---------|-----|
| time | Detection timestamp (HH:MM:SS) | VARCHAR | 8 | No | - | - |
| type | Attack type (UDP, SYN) | VARCHAR | 10 | No | - | - |
| src | Source IP:Port | VARCHAR | 51 | No | - | - |
| dst | Destination IP:Port | VARCHAR | 51 | No | - | - |
| packets | Packet count in flow | INTEGER | - | No | - | - |

---

### **ModelArtifact (Pickle Files)**

| Aspect | Details |
|--------|---------|
| Name | ModelArtifact |
| Alias | Trained Model Files |
| Where-used/how-used | Output of train_model.py; loaded by backend.py for inference |
| Content description | ModelArtifact = ddos_model.pkl + scaler.pkl + feature_names.pkl + label_encoder.pkl |

| File Name | Description | Type | Size | Format |
|-----------|-------------|------|------|--------|
| ddos_model.pkl | Trained RandomForest | Binary | ~1.6 MB | Pickle |
| scaler.pkl | StandardScaler params | Binary | ~1.4 KB | Pickle |
| feature_names.pkl | Feature name list | Binary | ~263 B | Pickle |
| label_encoder.pkl | Label encoder | Binary | ~494 B | Pickle |

---

# 6. Application Design

## 6.1 Sequence Diagrams

### Sequence Diagram 1: Live Detection Flow

```
┌─────────┐     ┌─────────┐     ┌──────────┐     ┌─────────┐     ┌────────┐
│  User   │     │ backend │     │NFStreamer│     │  Model  │     │ Status │
└────┬────┘     └────┬────┘     └────┬─────┘     └────┬────┘     └───┬────┘
     │               │               │                │              │
     │ sudo python   │               │                │              │
     │ backend.py    │               │                │              │
     │──────────────▶│               │                │              │
     │               │               │                │              │
     │               │ load_model()  │                │              │
     │               │───────────────────────────────▶│              │
     │               │               │                │              │
     │               │ Thread.start()│                │              │
     │               │──────────────▶│                │              │
     │               │               │                │              │
     │               │               │ for flow in    │              │
     │               │               │ streamer:      │              │
     │               │               │ ◀─────────────▶│              │
     │               │               │                │              │
     │               │ extract_flow_ │                │              │
     │               │ features(flow)│                │              │
     │               │◀──────────────│                │              │
     │               │               │                │              │
     │               │ scaler.transform(features)     │              │
     │               │───────────────────────────────▶│              │
     │               │               │                │              │
     │               │ model.predict(scaled)          │              │
     │               │───────────────────────────────▶│              │
     │               │               │                │              │
     │               │ label = 'UDP' │                │              │
     │               │◀──────────────────────────────│              │
     │               │               │                │              │
     │               │ status['attack_count'] += 1    │              │
     │               │───────────────────────────────────────────────▶
     │               │               │                │              │
     │               │ status['current_status'] = 'UNDER_ATTACK'     │
     │               │───────────────────────────────────────────────▶
     │               │               │                │              │
```

**Explanation:**
1. User starts backend with sudo privileges
2. Model artifacts loaded from pickle files
3. Capture thread spawned with network interface
4. NFStreamer captures flows continuously
5. Each flow: features extracted → scaled → classified
6. Status dictionary updated with results
7. Attack logs appended for dashboard display

---

### Sequence Diagram 2: Dashboard Status Update

```
┌─────────┐     ┌──────────┐     ┌─────────┐     ┌────────┐
│ Browser │     │dashboard │     │ Flask   │     │ Status │
│   (JS)  │     │  .html   │     │  API    │     │  Dict  │
└────┬────┘     └────┬─────┘     └────┬────┘     └───┬────┘
     │               │               │              │
     │ HTTP GET /    │               │              │
     │──────────────▶│               │              │
     │               │               │              │
     │ ◀─────────────│               │              │
     │  HTML Page    │               │              │
     │               │               │              │
     │ setInterval(  │               │              │
     │  1000ms)      │               │              │
     │──────────────▶│               │              │
     │               │               │              │
     │ fetch('/api/  │               │              │
     │  status')     │               │              │
     │───────────────────────────────▶              │
     │               │               │              │
     │               │               │ jsonify(     │
     │               │               │  status)     │
     │               │               │─────────────▶│
     │               │               │              │
     │               │               │◀─────────────│
     │◀──────────────────────────────│              │
     │  JSON Response│               │              │
     │               │               │              │
     │ updateUI(data)│               │              │
     │──────────────▶│               │              │
     │               │               │              │
     │ DOM Updates   │               │              │
     │◀──────────────│               │              │
```

**Explanation:**
1. Browser requests dashboard HTML from Flask
2. JavaScript initializes with 1-second polling interval
3. Each interval: fetch() calls /api/status endpoint
4. Flask returns current status dictionary as JSON
5. JavaScript updates DOM elements with new values
6. Visual indicators change based on status (SAFE/ATTACK)

---

## 6.2 State Diagrams

### State Diagram 1: Detection System States

```
                              ┌──────────────────┐
                              │                  │
                    ┌────────▶│   INITIALIZING   │
                    │         │                  │
                    │         └────────┬─────────┘
                    │                  │
                    │                  │ model_loaded &&
                    │                  │ capture_started
                    │                  ▼
                    │         ┌──────────────────┐
          startup   │         │                  │
          error     │    ┌───▶│      SAFE        │◀───┐
                    │    │    │                  │    │
                    │    │    └────────┬─────────┘    │
                    │    │             │              │
                    │    │             │ attack       │ consecutive_benign
                    │    │             │ detected     │ >= 20
                    │    │             ▼              │
                    │    │    ┌──────────────────┐    │
                    │    │    │                  │    │
                    │    │    │  UNDER_ATTACK    │────┘
                    │    │    │                  │
                    │    │    └────────┬─────────┘
                    │    │             │
                    │    │             │ capture_error
                    │    │             ▼
                    │    │    ┌──────────────────┐
                    │    │    │                  │
                    └────┼────│      ERROR       │
                         │    │                  │
                         │    └────────┬─────────┘
                         │             │
                         │             │ restart
                         └─────────────┘
```

**States:**
- **INITIALIZING**: System startup, loading models
- **SAFE**: Normal operation, no attacks detected
- **UNDER_ATTACK**: Active attack detected, showing alert
- **ERROR**: Capture or system failure

**Transitions:**
- INITIALIZING → SAFE: Model loaded successfully
- SAFE → UNDER_ATTACK: Attack flow classified
- UNDER_ATTACK → SAFE: 20 consecutive benign flows
- Any → ERROR: Exception in capture thread

---

### State Diagram 2: Flow Classification States

```
┌──────────────────┐
│                  │
│    CAPTURED      │
│                  │
└────────┬─────────┘
         │
         │ packets >= min_packets
         ▼
┌──────────────────┐
│                  │
│   EXTRACTING     │
│                  │
└────────┬─────────┘
         │
         │ features_valid
         ▼
┌──────────────────┐
│                  │
│    SCALING       │
│                  │
└────────┬─────────┘
         │
         │ scaled_features
         ▼
┌──────────────────┐
│                  │
│   CLASSIFYING    │
│                  │
└────────┬─────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌───────┐ ┌───────┐
│BENIGN │ │ATTACK │
└───────┘ └───────┘
```

---

## 6.3 GUI Design

### Dashboard Main Screen

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                        🛡️ ThreatGuard-AI                                    │
│                   REAL-TIME DDOS DETECTION SYSTEM                           │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                                                                      │   │
│   │                          🛡️                                         │   │
│   │                                                                      │   │
│   │                    NETWORK SAFE                                      │   │
│   │                   (Green glowing border)                             │   │
│   │                                                                      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐ ┌────────┐ │
│   │ Total Flows      │ │ Benign Traffic   │ │ Attacks Detected │ │ Uptime │ │
│   │      0           │ │      0           │ │      0           │ │00:00:00│ │
│   │                  │ │   (Green)        │ │   (Red)          │ │        │ │
│   └──────────────────┘ └──────────────────┘ └──────────────────┘ └────────┘ │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  RECENT ATTACK LOGS                                                  │   │
│   ├──────────┬──────────┬─────────────────┬─────────────────┬───────────┤   │
│   │  Time    │  Type    │  Source         │  Target         │  Packets  │   │
│   ├──────────┼──────────┼─────────────────┼─────────────────┼───────────┤   │
│   │          │          │  No recent attacks detected       │           │   │
│   └──────────┴──────────┴─────────────────┴─────────────────┴───────────┘   │
│                                                                              │
│   ● Live - Monitoring Active                Interface: enp11s0              │
│                                                                              │
│                      ThreatGuard-AI © 2024 | Final Year Project             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Dashboard Under Attack State

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│                        🛡️ ThreatGuard-AI                                    │
│                   REAL-TIME DDOS DETECTION SYSTEM                           │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  ████████████████████████████████████████████████████████████████   │   │
│   │  █                         🚨                                    █   │   │
│   │  █                                                               █   │   │
│   │  █                    UNDER ATTACK                               █   │   │
│   │  █                                                               █   │   │
│   │  █                  Attack Type: UDP                             █   │   │
│   │  █   (Red pulsing border with danger animation)                  █   │   │
│   │  ████████████████████████████████████████████████████████████████   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐ ┌────────┐ │
│   │ Total Flows      │ │ Benign Traffic   │ │ Attacks Detected │ │ Uptime │ │
│   │    1,234         │ │    1,100         │ │      134         │ │00:05:23│ │
│   └──────────────────┘ └──────────────────┘ └──────────────────┘ └────────┘ │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  RECENT ATTACK LOGS                                                  │   │
│   ├──────────┬──────────┬─────────────────┬─────────────────┬───────────┤   │
│   │  Time    │  Type    │  Source         │  Target         │  Packets  │   │
│   ├──────────┼──────────┼─────────────────┼─────────────────┼───────────┤   │
│   │ 14:32:15 │  UDP     │ 192.168.1.100   │ 10.0.0.1:80     │    156    │   │
│   │ 14:32:12 │  UDP     │ 192.168.1.101   │ 10.0.0.1:80     │    203    │   │
│   │ 14:32:08 │  UDP     │ 192.168.1.100   │ 10.0.0.1:443    │    189    │   │
│   └──────────┴──────────┴─────────────────┴─────────────────┴───────────┘   │
│                                                                              │
│   ● Live - Monitoring Active                Interface: enp11s0              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### DFD Level 1

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DFD Level 1                                     │
└─────────────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────┐
                    │    Network      │
                    │    Traffic      │
                    │   (External)    │
                    └────────┬────────┘
                             │
                             │ Raw Packets
                             ▼
              ┌──────────────────────────────┐
              │         1.0                   │
              │     Capture Flows             │
              │     (NFStreamer)              │
              └──────────────┬───────────────┘
                             │
                             │ Flow Objects
                             ▼
              ┌──────────────────────────────┐
              │         2.0                   │
              │    Extract Features           │
              │  (extract_flow_features)      │
              └──────────────┬───────────────┘
                             │
                             │ Feature Vector [12]
                             ▼
              ┌──────────────────────────────┐
              │         3.0                   │
              │    Scale Features             │       ┌─────────────────┐
              │    (StandardScaler)           │◀──────│   D1: Model     │
              └──────────────┬───────────────┘       │   Artifacts     │
                             │                        └─────────────────┘
                             │ Scaled Features
                             ▼
              ┌──────────────────────────────┐
              │         4.0                   │
              │    Classify Flow              │
              │    (RandomForest)             │
              └──────────────┬───────────────┘
                             │
                    ┌────────┴────────┐
                    │                 │
                    ▼                 ▼
           ┌──────────────┐  ┌──────────────┐
           │ BENIGN       │  │ ATTACK       │
           │              │  │              │
           └──────┬───────┘  └──────┬───────┘
                  │                 │
                  │                 │ Log Entry
                  │                 ▼
                  │        ┌─────────────────┐
                  │        │  D2: Attack     │
                  │        │  Logs           │
                  │        └─────────────────┘
                  │                 │
                  └────────┬────────┘
                           │
                           │ Status Update
                           ▼
              ┌──────────────────────────────┐
              │         5.0                   │
              │    Update Status              │
              │    (status dict)              │
              └──────────────┬───────────────┘
                             │
                             │ JSON
                             ▼
              ┌──────────────────────────────┐
              │         6.0                   │
              │    Serve Dashboard            │
              │    (Flask)                    │
              └──────────────┬───────────────┘
                             │
                             │ HTTP Response
                             ▼
                    ┌─────────────────┐
                    │    Browser      │
                    │    (User)       │
                    └─────────────────┘
```

**DFD Explanation:**
1. **Process 1.0**: NFStreamer captures raw network packets and assembles flows
2. **Process 2.0**: Extracts 12 statistical features from each flow
3. **Process 3.0**: Applies StandardScaler transformation using saved parameters
4. **Process 4.0**: Random Forest classifier predicts BENIGN or attack type
5. **Process 5.0**: Updates global status dictionary with results
6. **Process 6.0**: Flask serves status via API to browser dashboard

---

# 7. References

| Ref | Title | Author/Org | Date | Source |
|-----|-------|------------|------|--------|
| 1 | CIC-DDoS2019 Dataset | Canadian Institute for Cybersecurity | 2019 | unb.ca/cic |
| 2 | NFStream Documentation | NFStream Project | 2024 | nfstream.org |
| 3 | scikit-learn User Guide | scikit-learn developers | 2024 | scikit-learn.org |
| 4 | Flask Documentation | Pallets Projects | 2024 | flask.palletsprojects.com |
| 5 | Random Forests Paper | Leo Breiman | 2001 | Machine Learning Journal |
| 6 | IEEE 1016-2009 | IEEE | 2009 | Software Design Descriptions |
| 7 | ThreatGuard-AI SRS | ThreatGuard-AI Team | 2026 | Project Documentation |

---

# 8. Appendices

## Appendix A: Feature Definitions

| Feature | Definition | Unit | Typical Range |
|---------|------------|------|---------------|
| flow_duration_ms | Total flow duration | ms | 1 - 120000 |
| total_fwd_packets | Source to destination packets | count | 1 - 100000 |
| total_bwd_packets | Destination to source packets | count | 0 - 100000 |
| flow_bytes_per_sec | Data transfer rate | bytes/s | 0 - 1e9 |
| flow_packets_per_sec | Packet rate | packets/s | 0 - 100000 |
| fwd_packet_length_mean | Average forward packet size | bytes | 0 - 1500 |
| bwd_packet_length_mean | Average backward packet size | bytes | 0 - 1500 |
| flow_iat_mean | Mean inter-arrival time | ms | 0 - 60000 |
| fwd_packet_length_max | Maximum forward packet size | bytes | 0 - 65535 |
| bwd_packet_length_max | Maximum backward packet size | bytes | 0 - 65535 |
| fwd_iat_mean | Forward IAT mean | ms | 0 - 60000 |
| bwd_iat_mean | Backward IAT mean | ms | 0 - 60000 |

## Appendix B: Model Parameters

```python
RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    min_samples_split=10,
    min_samples_leaf=5,
    random_state=42,
    n_jobs=-1,
    class_weight={0: 1, 1: 1}
)
```

## Appendix C: API Response Schema

```json
{
  "current_status": "SAFE | UNDER_ATTACK | INITIALIZING | ERROR",
  "attack_type": "UDP | SYN | null",
  "total_flows": 0,
  "benign_count": 0,
  "attack_count": 0,
  "last_attack_time": "ISO8601 timestamp | null",
  "uptime_seconds": 0,
  "consecutive_benign": 0,
  "is_capturing": true,
  "interface": "enp11s0",
  "attack_logs": [
    {
      "time": "HH:MM:SS",
      "type": "UDP",
      "src": "IP:Port",
      "dst": "IP:Port",
      "packets": 0
    }
  ]
}
```

---

**Document End**

*This SDS document is prepared for ThreatGuard-AI, a Final Year Project for educational purposes.*
