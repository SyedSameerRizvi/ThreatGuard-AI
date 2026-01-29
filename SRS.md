# Software Requirements Specification (SRS)
## ThreatGuard-AI: Real-Time DDoS Detection System

**Document Version:** 1.0  
**Date:** January 29, 2026  
**Project:** ThreatGuard-AI  
**Author:** ThreatGuard-AI Team

---

# Table of Contents

1. [Introduction](#1-introduction)
   - 1.1 [Purpose of Document](#11-purpose-of-document)
   - 1.2 [Intended Audience](#12-intended-audience)
   - 1.3 [Abbreviations](#13-abbreviations)
2. [Overall System Description](#2-overall-system-description)
   - 2.1 [Project Background](#21-project-background)
   - 2.2 [Problem Statement](#22-problem-statement)
   - 2.3 [Project Scope](#23-project-scope)
   - 2.4 [Not In Scope](#24-not-in-scope)
   - 2.5 [Project Objectives](#25-project-objectives)
   - 2.6 [Stakeholders & Affected Groups](#26-stakeholders--affected-groups)
   - 2.7 [Operating Environment](#27-operating-environment)
   - 2.8 [System Constraints](#28-system-constraints)
   - 2.9 [Assumptions & Dependencies](#29-assumptions--dependencies)
3. [External Interface Requirements](#3-external-interface-requirements)
   - 3.1 [Hardware Interfaces](#31-hardware-interfaces)
   - 3.2 [Software Interfaces](#32-software-interfaces)
   - 3.3 [Communications Interfaces](#33-communications-interfaces)
4. [System Functions / Functional Requirements](#4-system-functions--functional-requirements)
   - 4.1 [System Functions](#41-system-functions)
   - 4.2 [Use Cases](#42-use-cases)
5. [Non-Functional Requirements](#5-non-functional-requirements)
   - 5.1 [Performance Requirements](#51-performance-requirements)
   - 5.2 [Safety Requirements](#52-safety-requirements)
   - 5.3 [Security Requirements](#53-security-requirements)
   - 5.4 [Reliability Requirements](#54-reliability-requirements)
   - 5.5 [Usability Requirements](#55-usability-requirements)
   - 5.6 [Supportability Requirements](#56-supportability-requirements)
   - 5.7 [User Documentation](#57-user-documentation)
6. [References](#6-references)

---

# 1. Introduction

## 1.1 Purpose of Document

This Software Requirements Specification (SRS) document provides a comprehensive description of the functional and non-functional requirements for ThreatGuard-AI, a real-time DDoS (Distributed Denial of Service) detection system. This document serves as the primary reference for the development team, stakeholders, and evaluators throughout the project lifecycle.

The purpose of this SRS is to:
- Define the complete system requirements for ThreatGuard-AI
- Establish a baseline for validation and verification of the system
- Provide a framework for planning, designing, and implementing the system
- Document the scope, constraints, and assumptions of the project
- Serve as a contract between the development team and stakeholders

## 1.2 Intended Audience

This document is intended for the following audiences:

| Audience | Purpose |
|----------|---------|
| **Development Team** | Use as the primary reference for system implementation, understanding functional requirements and technical specifications |
| **Project Supervisors/Evaluators** | Evaluate the project scope, technical feasibility, and completeness of requirements |
| **Quality Assurance/Testers** | Develop test cases and validation criteria based on documented requirements |
| **System Administrators** | Understand deployment requirements, operating environment, and system constraints |
| **Network Security Professionals** | Evaluate the detection capabilities and integration potential with existing security infrastructure |
| **Future Maintainers** | Reference for system maintenance, enhancements, and troubleshooting |

## 1.3 Abbreviations

| Abbreviation | Full Form |
|--------------|-----------|
| API | Application Programming Interface |
| BENIGN | Normal/Legitimate Network Traffic |
| CPU | Central Processing Unit |
| CSV | Comma-Separated Values |
| DDoS | Distributed Denial of Service |
| FYP | Final Year Project |
| GB | Gigabyte |
| HTML | Hypertext Markup Language |
| HTTP | Hypertext Transfer Protocol |
| IAT | Inter-Arrival Time |
| IP | Internet Protocol |
| JSON | JavaScript Object Notation |
| MB | Megabyte |
| ML | Machine Learning |
| ms | Milliseconds |
| NFStream | Network Flow Stream Library |
| OS | Operating System |
| PCAP | Packet Capture |
| PKL | Pickle (Python Serialization Format) |
| RAM | Random Access Memory |
| REST | Representational State Transfer |
| ROC | Receiver Operating Characteristic |
| SRS | Software Requirements Specification |
| SYN | Synchronize (TCP Flag) |
| TCP | Transmission Control Protocol |
| UDP | User Datagram Protocol |
| UI | User Interface |

---

# 2. Overall System Description

## 2.1 Project Background

ThreatGuard-AI is developed as a Final Year Project aimed at addressing the growing concern of DDoS attacks in modern network infrastructure. Traditional signature-based intrusion detection systems often fail to identify novel attack patterns, while rule-based systems require constant updates and expert configuration.

The proliferation of IoT devices and increasing bandwidth availability has made it easier for malicious actors to launch sophisticated DDoS attacks. Organizations of all sizes face the risk of service disruption, financial losses, and reputational damage from these attacks. The need for intelligent, adaptive detection systems that can identify attack patterns in real-time has become critical.

ThreatGuard-AI leverages machine learning techniques, specifically Random Forest classification, combined with network flow analysis using NFStream to provide an automated, real-time DDoS detection solution. The system is trained on the CIC-DDoS2019 dataset, a widely recognized benchmark dataset for DDoS detection research, ensuring robust and validated detection capabilities.

## 2.2 Problem Statement

Organizations lack accessible, real-time DDoS detection tools that leverage machine learning for accurate attack identification without requiring specialized expertise, leading to delayed threat response and potential service disruptions.

## 2.3 Project Scope

The ThreatGuard-AI system includes the following features and functionalities:

### Feature Extraction Module
- Process PCAP (Packet Capture) files using NFStream library
- Extract 12 flow-based network features essential for attack detection
- Support for multiple PCAP file processing in batch mode
- Timestamp-based labeling for supervised learning
- Feature validation and outlier handling

### Model Training Module
- Random Forest classifier training with configurable hyperparameters
- Class imbalance handling through undersampling
- Model performance evaluation with accuracy, precision, recall, and F1-score metrics
- Confusion matrix and ROC curve visualization
- Model serialization for deployment

### Live Detection Module
- Real-time network traffic capture on specified network interfaces
- Continuous flow analysis and classification
- Attack type identification (BENIGN vs UDP Flood)
- Detection logging with timestamps and flow details
- Console-based status reporting

### Web Dashboard Module
- Modern, responsive web interface for monitoring
- Real-time status display (NETWORK SAFE / UNDER ATTACK)
- Network statistics visualization (total flows, benign count, attack count)
- System uptime tracking
- Attack log table with detailed information
- WebSocket-based live updates

### Supported Attack Types
- BENIGN (normal traffic) classification
- UDP Flood detection
- SYN Flood detection (training support)

## 2.4 Not In Scope

The following items are explicitly excluded from the current project scope:

| Category | Exclusion |
|----------|-----------|
| **Attack Types** | Detection of application-layer attacks (HTTP flood, Slowloris), DNS amplification attacks, NTP reflection attacks |
| **Deployment** | Cloud deployment, Docker containerization, multi-node distributed detection |
| **Features** | Automatic attack mitigation/blocking, email/SMS alerting, integration with external SIEM systems |
| **Platform** | Windows native support, mobile applications, macOS native support |
| **Network** | IPv6 traffic analysis, encrypted traffic (TLS/SSL) deep inspection, VLAN-aware detection |
| **Data** | Long-term data storage/archival, historical attack pattern analysis, compliance reporting |
| **Authentication** | User authentication for web dashboard, role-based access control, multi-tenant support |

## 2.5 Project Objectives

| ID | Objective | Measurable Criteria |
|----|-----------|---------------------|
| O1 | Achieve high detection accuracy | Model accuracy ≥ 95% on test dataset |
| O2 | Enable real-time detection | Detection latency < 1 second from flow completion |
| O3 | Provide intuitive monitoring interface | Web dashboard accessible via standard browser |
| O4 | Support common attack types | Detection of UDP and SYN flood attacks |
| O5 | Ensure minimal false positives | Precision score ≥ 90% for attack classification |
| O6 | Enable automated feature extraction | Process PCAP files without manual intervention |
| O7 | Provide comprehensive logging | All detections logged with timestamp and flow details |
| O8 | Achieve portability | System deployable on standard Ubuntu Linux systems |

## 2.6 Stakeholders & Affected Groups

| Stakeholder | Role | Interest/Impact |
|-------------|------|-----------------|
| **Project Supervisor** | Academic oversight | Evaluation of technical merit, methodology, and documentation |
| **Development Team** | System implementation | Design, development, testing, and deployment |
| **Network Administrators** | End users | Deploy and operate the detection system |
| **Security Analysts** | End users | Monitor alerts and investigate detected attacks |
| **Organization IT Management** | Decision makers | Evaluate effectiveness for security investment decisions |
| **Network Users** | Indirect beneficiaries | Benefit from protected network services |
| **Academic Evaluators** | Assessment | Grade the FYP based on technical achievement and innovation |
| **Future Researchers** | Reference users | Use as baseline for further DDoS detection research |

## 2.7 Operating Environment

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | Dual-core processor | Quad-core processor |
| **RAM** | 4 GB | 8 GB or higher |
| **Storage** | 10 GB free space | 50 GB SSD |
| **Network** | Ethernet adapter with promiscuous mode support | Dedicated network monitoring interface |

### Software Requirements

| Component | Requirement |
|-----------|-------------|
| **Operating System** | Ubuntu Linux 20.04 LTS or later |
| **Python** | Python 3.8 or higher |
| **Web Browser** | Modern browser (Chrome, Firefox, Edge) for dashboard access |
| **Network Library** | libpcap-dev installed |
| **Privileges** | Root/sudo access for network capture |

### Runtime Environment

| Component | Technology |
|-----------|------------|
| **ML Framework** | scikit-learn |
| **Network Analysis** | NFStream |
| **Web Server** | Flask |
| **Data Processing** | pandas, numpy |
| **Visualization** | matplotlib, seaborn |

## 2.8 System Constraints

### Technical Constraints
- **Network Capture**: Requires root/sudo privileges for live network capture
- **Operating System**: Currently limited to Linux-based systems
- **Processing Power**: Real-time detection performance depends on available CPU resources
- **Memory**: Large PCAP files require significant RAM for processing
- **Network Interface**: Must support promiscuous mode operation

### Regulatory Constraints
- **Privacy**: Network monitoring must comply with organizational privacy policies
- **Data Protection**: Captured traffic data must be handled according to applicable data protection regulations
- **Educational Use**: System designed for educational/research purposes only

### Timeline Constraints
- Development timeline aligned with FYP academic schedule

## 2.9 Assumptions & Dependencies

### Assumptions

1. The network interface is properly configured and supports promiscuous mode
2. The CIC-DDoS2019 dataset accurately represents real-world attack patterns
3. UDP and SYN flood attacks are the primary DDoS threats to be addressed
4. Users have basic Linux command-line knowledge for system operation
5. Network traffic patterns remain consistent with training data distribution
6. The detection environment has sufficient computational resources
7. Ground truth labels in training data are accurate

### Dependencies

| Dependency | Description | Version |
|------------|-------------|---------|
| **NFStream** | Core network flow analysis library | Latest stable |
| **scikit-learn** | Machine learning model training and inference | 1.0+ |
| **pandas** | Data manipulation and CSV handling | 1.3+ |
| **numpy** | Numerical computations | 1.20+ |
| **Flask** | Web application framework | 2.0+ |
| **matplotlib** | Visualization for training metrics | 3.4+ |
| **seaborn** | Statistical visualization | 0.11+ |
| **libpcap** | Packet capture library | System package |
| **joblib** | Model serialization | 1.0+ |

---

# 3. External Interface Requirements

## 3.1 Hardware Interfaces

### Network Interface Card (NIC)

| Attribute | Specification |
|-----------|---------------|
| **Interface Name** | System-dependent (e.g., enp11s0, eth0) |
| **Mode** | Promiscuous mode for traffic capture |
| **Physical Address** | Standard MAC address format |
| **Expected Behavior** | Capture all network packets on the segment, not just those destined for the host |
| **Data Format** | Raw Ethernet frames |
| **Data Rate** | Up to 1 Gbps (dependent on NIC capability) |

### Logical Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Interface                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   libpcap   │───▶│  NFStream   │───▶│  Feature    │     │
│  │   Capture   │    │   Parser    │    │  Extractor  │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### Hardware Interface Requirements

| Requirement ID | Description |
|----------------|-------------|
| HI-01 | System shall interface with any Linux-compatible network interface |
| HI-02 | System shall access raw packet data through libpcap library |
| HI-03 | System shall handle network interfaces operating at 100 Mbps to 1 Gbps |
| HI-04 | System shall detect and report interface-related errors |

## 3.2 Software Interfaces

### External Software Applications

| Application | Owner | Interface Type | Description |
|-------------|-------|----------------|-------------|
| **NFStream** | NFStream Project | Python Library | Network flow extraction and feature computation from packet captures |
| **scikit-learn** | scikit-learn developers | Python Library | Machine learning model training, inference, and preprocessing (StandardScaler, RandomForestClassifier) |
| **Flask** | Pallets Projects | Python Library | HTTP web server for serving dashboard and REST API endpoints |
| **pandas** | pandas development team | Python Library | DataFrame operations for feature data manipulation |
| **joblib** | Joblib developers | Python Library | Model persistence (serialization/deserialization of .pkl files) |

### Model Interface

| File | Purpose | Format |
|------|---------|--------|
| `ddos_model.pkl` | Trained Random Forest classifier | Python Pickle |
| `scaler.pkl` | Feature standardization parameters | Python Pickle |
| `feature_names.pkl` | List of expected feature names | Python Pickle |
| `label_encoder.pkl` | Label encoding for attack classes | Python Pickle |

### Data File Interfaces

| File Type | Format | Description |
|-----------|--------|-------------|
| **Input PCAP** | Binary PCAP | Raw network capture files for training/testing |
| **Feature CSV** | CSV with headers | Extracted features with labels |
| **Log Files** | Plain text | Detection events and system logs |
| **Metrics** | Plain text | Training performance metrics |

## 3.3 Communications Interfaces

### HTTP/REST API

| Endpoint | Method | Description | Response Format |
|----------|--------|-------------|-----------------|
| `/` | GET | Serve web dashboard HTML | HTML |
| `/api/status` | GET | Return current detection status | JSON |

### API Response Schema

```json
{
  "current_status": "SAFE | UNDER_ATTACK | INITIALIZING",
  "attack_type": "UDP | SYN | null",
  "total_flows": <integer>,
  "benign_count": <integer>,
  "attack_count": <integer>,
  "uptime_seconds": <integer>,
  "interface": "<string>",
  "attack_logs": [
    {
      "time": "<timestamp>",
      "type": "<attack_type>",
      "src": "<source_ip>:<port>",
      "dst": "<dest_ip>:<port>",
      "packets": <integer>
    }
  ]
}
```

### Network Communication

| Protocol | Port | Description |
|----------|------|-------------|
| **HTTP** | 5000 | Flask web server for dashboard access |
| **Raw Sockets** | N/A | Network packet capture (via libpcap) |

### Dashboard Data Flow

```
┌─────────────┐     HTTP GET /api/status     ┌─────────────┐
│   Browser   │◀────────────────────────────▶│   Flask     │
│  Dashboard  │        JSON Response         │   Server    │
└─────────────┘                              └─────────────┘
      │                                            │
      │  Polling every 1 second                    │
      │                                            ▼
      │                                     ┌─────────────┐
      └────────────────────────────────────▶│  Detection  │
            UI Updates                      │   Engine    │
                                            └─────────────┘
```

---

# 4. System Functions / Functional Requirements

## 4.1 System Functions

| Ref # | Functions | Category | Attribute | Details & Boundary Constraints |
|-------|-----------|----------|-----------|-------------------------------|
| **Feature Extraction** |||||
| R1.1 | Process PCAP files for feature extraction | Evident | File Processing | System shall process PCAP files up to 500 MB each; batch processing of multiple files supported |
| R1.2 | Extract 12 flow-based network features | Evident | Data Extraction | Features include: flow_duration_ms, total_fwd_packets, total_bwd_packets, flow_bytes_per_sec, flow_packets_per_sec, fwd_packet_length_mean, bwd_packet_length_mean, flow_iat_mean, fwd_packet_length_max, bwd_packet_length_max, fwd_iat_mean, bwd_iat_mean |
| R1.3 | Apply timestamp-based labeling | Hidden | Data Labeling | Labels assigned based on CIC-DDoS2019 attack timeline; supports BENIGN, UDP, and SYN labels |
| R1.4 | Validate and clean extracted features | Hidden | Data Quality | Remove NaN values, handle infinity, clip extreme outliers (>10 standard deviations) |
| R1.5 | Export features to CSV format | Evident | Data Export | Output CSV with headers, supports configurable output path |
| **Model Training** |||||
| R2.1 | Load and balance training data | Hidden | Data Preparation | Undersample majority classes to address class imbalance; minimum 10,000 samples per class |
| R2.2 | Train Random Forest classifier | Evident | Model Training | Configurable parameters: n_estimators (default 100), max_depth (default 20), class_weight='balanced' |
| R2.3 | Evaluate model performance | Evident | Model Evaluation | Calculate accuracy, precision, recall, F1-score; per-class metrics required |
| R2.4 | Generate confusion matrix visualization | Evident | Visualization | PNG output with annotated confusion matrix; output path: logs/confusion_matrix.png |
| R2.5 | Generate ROC curves | Evident | Visualization | Multi-class ROC curves with AUC values; output path: logs/roc_curves.png |
| R2.6 | Serialize trained model artifacts | Evident | Model Persistence | Save model, scaler, encoder, feature_names as .pkl files |
| **Live Detection** |||||
| R3.1 | Capture live network traffic | Evident | Network Capture | Requires root privileges; configurable network interface; minimum 3 packets per flow |
| R3.2 | Extract features from live flows | Hidden | Feature Extraction | Identical feature extraction as training; real-time processing |
| R3.3 | Classify network flows | Evident | Classification | Binary/multi-class classification; outputs BENIGN or attack type |
| R3.4 | Log detected attacks | Evident | Logging | Log to file with timestamp, source/destination IP:port, packet count, attack type |
| R3.5 | Console status reporting | Evident | Output | Real-time terminal output of detection results |
| **Web Dashboard** |||||
| R4.1 | Serve responsive web interface | Evident | UI | HTML5/CSS3/JavaScript; mobile-responsive design |
| R4.2 | Display real-time network status | Evident | UI | Visual indicators: NETWORK SAFE (green shield) or UNDER ATTACK (red alert with animation) |
| R4.3 | Show attack type information | Evident | UI | Display specific attack type (UDP, SYN) when attack detected |
| R4.4 | Display network statistics | Evident | UI | Show total flows, benign count, attack count with comma formatting |
| R4.5 | Track system uptime | Evident | UI | Display uptime in HH:MM:SS format |
| R4.6 | Provide REST API status endpoint | Hidden | API | JSON response at /api/status; 1-second polling interval |
| R4.7 | Display attack log table | Evident | UI | Tabular display of recent attacks with time, type, source, destination, packets |
| R4.8 | Show connection status indicator | Evident | UI | Live connection dot with "Monitoring Active" or "Connection Lost" text |

## 4.2 Use Cases

### 4.2.1 List of Actors

| Actor ID | Actor Name | Description |
|----------|------------|-------------|
| A1 | Network Administrator | Primary user who deploys, configures, and monitors the detection system |
| A2 | Security Analyst | User who reviews detection alerts and investigates potential attacks |
| A3 | Data Scientist | User who trains and evaluates the machine learning model |
| A4 | Network Interface | External system providing packet data |
| A5 | File System | External system for storing/retrieving PCAP files and model artifacts |

### 4.2.2 List of Use Cases

| Use Case ID | Use Case Name | Brief Description |
|-------------|---------------|-------------------|
| UC-01 | Extract Features from PCAP | Data Scientist processes PCAP files to extract network flow features for model training |
| UC-02 | Train Detection Model | Data Scientist trains the Random Forest classifier using extracted features |
| UC-03 | Start Live Detection | Network Administrator starts real-time network monitoring on a specified interface |
| UC-04 | View Dashboard | Security Analyst monitors network status through the web dashboard |
| UC-05 | View Attack Logs | Security Analyst reviews logged attack incidents |
| UC-06 | Stop Detection | Network Administrator gracefully stops the detection system |
| UC-07 | Verify Installation | Network Administrator validates system installation and dependencies |
| UC-08 | Configure Detection Parameters | Network Administrator adjusts detection thresholds and interface settings |

### 4.2.3 Use Case Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ThreatGuard-AI System                               │
│                                                                              │
│    ┌─────────────────────────────────────────────────────────────────────┐  │
│    │                        Feature Extraction                            │  │
│    │                                                                      │  │
│    │     ┌─────────────────┐          ┌─────────────────┐                │  │
│    │     │ UC-01: Extract  │          │ UC-02: Train    │                │  │
│    │     │ Features from   │─────────▶│ Detection       │                │  │
│    │     │ PCAP            │          │ Model           │                │  │
│    │     └────────┬────────┘          └────────┬────────┘                │  │
│    │              │                            │                          │  │
│    └──────────────┼────────────────────────────┼──────────────────────────┘  │
│                   │                            │                              │
│         ┌────────▼────────┐          ┌────────▼────────┐                     │
│         │   Data          │          │   Data          │                     │
│         │   Scientist     │          │   Scientist     │                     │
│         └─────────────────┘          └─────────────────┘                     │
│                                                                              │
│    ┌─────────────────────────────────────────────────────────────────────┐  │
│    │                        Live Detection                                │  │
│    │                                                                      │  │
│    │     ┌─────────────────┐          ┌─────────────────┐                │  │
│    │     │ UC-03: Start    │          │ UC-06: Stop     │                │  │
│    │     │ Live Detection  │          │ Detection       │                │  │
│    │     └────────┬────────┘          └────────┬────────┘                │  │
│    │              │                            │                          │  │
│    └──────────────┼────────────────────────────┼──────────────────────────┘  │
│                   │                            │                              │
│         ┌────────▼────────┐          ┌────────▼────────┐                     │
│         │   Network       │          │   Network       │                     │
│         │   Administrator │          │   Administrator │                     │
│         └─────────────────┘          └─────────────────┘                     │
│                                                                              │
│    ┌─────────────────────────────────────────────────────────────────────┐  │
│    │                        Monitoring & Analysis                         │  │
│    │                                                                      │  │
│    │     ┌─────────────────┐          ┌─────────────────┐                │  │
│    │     │ UC-04: View     │          │ UC-05: View     │                │  │
│    │     │ Dashboard       │          │ Attack Logs     │                │  │
│    │     └────────┬────────┘          └────────┬────────┘                │  │
│    │              │                            │                          │  │
│    └──────────────┼────────────────────────────┼──────────────────────────┘  │
│                   │                            │                              │
│         ┌────────▼────────┐          ┌────────▼────────┐                     │
│         │   Security      │          │   Security      │                     │
│         │   Analyst       │          │   Analyst       │                     │
│         └─────────────────┘          └─────────────────┘                     │
│                                                                              │
│    ┌─────────────────────────────────────────────────────────────────────┐  │
│    │                        System Administration                         │  │
│    │                                                                      │  │
│    │     ┌─────────────────┐          ┌─────────────────┐                │  │
│    │     │ UC-07: Verify   │          │ UC-08: Configure│                │  │
│    │     │ Installation   │          │ Parameters      │                │  │
│    │     └────────┬────────┘          └────────┬────────┘                │  │
│    │              │                            │                          │  │
│    └──────────────┼────────────────────────────┼──────────────────────────┘  │
│                   │                            │                              │
│         ┌────────▼────────┐          ┌────────▼────────┐                     │
│         │   Network       │          │   Network       │                     │
│         │   Administrator │          │   Administrator │                     │
│         └─────────────────┘          └─────────────────┘                     │
│                                                                              │
│    ┌─────────────────────────────────────────────────────────────────────┐  │
│    │                        External Systems                              │  │
│    │                                                                      │  │
│    │     ┌─────────────────┐          ┌─────────────────┐                │  │
│    │     │   Network       │          │   File System   │                │  │
│    │     │   Interface     │          │                 │                │  │
│    │     └─────────────────┘          └─────────────────┘                │  │
│    │                                                                      │  │
│    └─────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2.4 Description of Use Cases

---

#### UC-01: Extract Features from PCAP

| Attribute | Description |
|-----------|-------------|
| **Name** | Extract Features from PCAP |
| **Actors** | Data Scientist, File System |
| **Purpose** | Process PCAP files to extract labeled network flow features for machine learning model training |
| **Description** | The Data Scientist initiates feature extraction from stored PCAP files. The system uses NFStream to parse the files, extracts 12 flow-based features, applies timestamp-based labeling, validates the features, and exports them as a CSV file for model training. |
| **Cross References** | R1.1, R1.2, R1.3, R1.4, R1.5 |
| **Pre-Conditions** | 1. PCAP files are present in the specified directory. 2. Virtual environment is activated. 3. Required dependencies are installed. |
| **Successful Post-Conditions** | 1. Feature CSV file is created at specified output path. 2. Statistics are displayed showing feature distribution. 3. Training log is updated. |
| **Failure Post-Conditions** | 1. Error message displayed indicating failure reason. 2. No output file created or partial file removed. 3. Error logged to console. |

**Typical Course of Events:**

| Step | Actor Action | System Response |
|------|--------------|-----------------|
| 1 | Data Scientist activates virtual environment | System confirms activation |
| 2 | Data Scientist executes `python src/extract_features.py` with optional arguments | System displays startup banner and configuration |
| 3 | - | System scans PCAP directory and reports file count |
| 4 | - | System processes each PCAP file sequentially with progress indicator |
| 5 | - | System extracts flows using NFStream for each file |
| 6 | - | System applies timestamp-based labeling (BENIGN/UDP/SYN) |
| 7 | - | System validates features and removes invalid entries |
| 8 | - | System exports features to CSV file |
| 9 | - | System displays extraction statistics (total flows, class distribution) |

**Alternative Courses:**

| Condition | System Response |
|-----------|-----------------|
| No PCAP files found | Display error "No PCAP files found in directory" and exit |
| NFStream import fails | Display dependency error and installation instructions |
| Invalid PCAP file | Log warning and skip to next file |
| Disk full | Display error and exit gracefully |
| All flows filtered | Display warning about minimum packet threshold |

---

#### UC-02: Train Detection Model

| Attribute | Description |
|-----------|-------------|
| **Name** | Train Detection Model |
| **Actors** | Data Scientist, File System |
| **Purpose** | Train a Random Forest classifier to detect DDoS attacks using extracted features |
| **Description** | The Data Scientist initiates model training using the extracted feature CSV. The system loads and balances the data, trains a Random Forest classifier, evaluates performance, generates visualizations, and saves the trained model artifacts. |
| **Cross References** | R2.1, R2.2, R2.3, R2.4, R2.5, R2.6 |
| **Pre-Conditions** | 1. Feature CSV file exists with labeled data. 2. Virtual environment is activated. 3. Sufficient RAM for training (minimum 4 GB). |
| **Successful Post-Conditions** | 1. Model files saved (ddos_model.pkl, scaler.pkl, feature_names.pkl, label_encoder.pkl). 2. Confusion matrix and ROC curves generated in logs/. 3. Training metrics saved to training_metrics.txt. 4. Model achieves accuracy ≥ 95%. |
| **Failure Post-Conditions** | 1. Error message displayed. 2. Training log records failure reason. 3. No model files created. |

**Typical Course of Events:**

| Step | Actor Action | System Response |
|------|--------------|-----------------|
| 1 | Data Scientist executes `python src/train_model.py` | System displays training banner and configuration |
| 2 | - | System loads feature CSV and reports shape |
| 3 | - | System balances classes through undersampling |
| 4 | - | System splits data into training (80%) and test (20%) sets |
| 5 | - | System applies feature scaling using StandardScaler |
| 6 | - | System trains Random Forest with configured parameters |
| 7 | - | System evaluates model on test set |
| 8 | - | System displays accuracy, precision, recall, F1-score |
| 9 | - | System generates and saves confusion matrix plot |
| 10 | - | System generates and saves ROC curves |
| 11 | - | System serializes model artifacts to models/ directory |
| 12 | - | System saves training metrics to text file |

**Alternative Courses:**

| Condition | System Response |
|-----------|-----------------|
| Feature file not found | Display error with expected path and exit |
| Insufficient samples per class | Display warning, proceed with available data |
| Memory error during training | Display error, suggest reducing dataset size |
| Training accuracy < 80% | Display warning about poor model performance |

---

#### UC-03: Start Live Detection

| Attribute | Description |
|-----------|-------------|
| **Name** | Start Live Detection |
| **Actors** | Network Administrator, Network Interface |
| **Purpose** | Begin real-time network traffic monitoring and attack detection |
| **Description** | The Network Administrator starts the live detection system on a specified network interface. The system loads trained model artifacts, initiates packet capture, processes flows in real-time, classifies traffic, and displays detection results. |
| **Cross References** | R3.1, R3.2, R3.3, R3.4, R3.5 |
| **Pre-Conditions** | 1. Trained model files exist in models/. 2. User has root/sudo privileges. 3. Specified network interface exists and is up. 4. Virtual environment is activated. |
| **Successful Post-Conditions** | 1. System is capturing and analyzing network traffic. 2. Detection results are displayed in console. 3. Attacks are logged to detections.log. 4. System can be gracefully terminated. |
| **Failure Post-Conditions** | 1. Error message displayed (permission denied, interface not found, model not found). 2. System exits without capturing traffic. |

**Typical Course of Events:**

| Step | Actor Action | System Response |
|------|--------------|-----------------|
| 1 | Network Administrator executes `sudo venv/bin/python src/capture_live.py <interface>` | System checks for root privileges |
| 2 | - | System loads model artifacts from models/ |
| 3 | - | System validates network interface availability |
| 4 | - | System displays "Starting capture on <interface>" |
| 5 | - | System begins NFStream capture in monitoring mode |
| 6 | - | For each completed flow, system extracts features |
| 7 | - | System scales features using loaded scaler |
| 8 | - | System classifies flow using Random Forest model |
| 9 | - | System displays classification result (BENIGN/ATTACK) |
| 10 | - | If attack detected, system logs to detections.log |
| 11 | Administrator sends interrupt signal (Ctrl+C) | System gracefully stops capture and displays summary |

**Alternative Courses:**

| Condition | System Response |
|-----------|-----------------|
| Not running as root | Display "Permission denied. Run with sudo." and exit |
| Interface not found | Display list of available interfaces and exit |
| Model files missing | Display path to expected files and exit |
| No traffic detected for 60s | Display warning about quiet network |
| Capture error | Log error, attempt to restart capture |

---

#### UC-04: View Dashboard

| Attribute | Description |
|-----------|-------------|
| **Name** | View Dashboard |
| **Actors** | Security Analyst, Network Administrator |
| **Purpose** | Monitor real-time network security status through web interface |
| **Description** | The user accesses the web dashboard in a browser to view current network status, attack statistics, and detection logs. The dashboard auto-refreshes to show live updates. |
| **Cross References** | R4.1, R4.2, R4.3, R4.4, R4.5, R4.6, R4.7, R4.8 |
| **Pre-Conditions** | 1. Backend server is running (`python src/backend.py`). 2. Browser has network access to server (localhost:5000). 3. Live detection is active. |
| **Successful Post-Conditions** | 1. Dashboard displays current network status. 2. Statistics update in real-time. 3. Attack logs visible when applicable. |
| **Failure Post-Conditions** | 1. Browser shows "Connection Refused" or "Connection Lost". 2. Dashboard displays offline indicator. |

**Typical Course of Events:**

| Step | Actor Action | System Response |
|------|--------------|-----------------|
| 1 | User opens browser and navigates to http://localhost:5000 | Server responds with dashboard HTML |
| 2 | - | Browser renders dashboard with initial loading state |
| 3 | - | Dashboard JavaScript initiates /api/status polling |
| 4 | - | Server returns JSON with current detection status |
| 5 | - | Dashboard updates status display (SAFE or UNDER ATTACK) |
| 6 | - | Dashboard updates statistics (flows, benign, attacks) |
| 7 | - | Dashboard updates attack log table if attacks detected |
| 8 | - | Dashboard continues polling every 1 second |
| 9 | User observes status changes as attacks occur/stop | Dashboard visually reflects changes with animations |

**Alternative Courses:**

| Condition | System Response |
|-----------|-----------------|
| Server not running | Browser displays connection refused error |
| API fetch fails | Dashboard shows "Connection Lost" with red dot |
| Network latency > 5s | Dashboard may show stale data briefly |

---

#### UC-05: View Attack Logs

| Attribute | Description |
|-----------|-------------|
| **Name** | View Attack Logs |
| **Actors** | Security Analyst |
| **Purpose** | Review historical attack detection records for incident analysis |
| **Description** | The Security Analyst accesses attack logs to review detected incidents, investigate attack patterns, and gather forensic information including timestamps, source/destination IPs, and attack types. |
| **Cross References** | R3.4, R4.7 |
| **Pre-Conditions** | 1. Detection has been running. 2. Attacks have been detected and logged. 3. User has file system access to logs/. |
| **Successful Post-Conditions** | 1. Analyst can view chronological attack history. 2. Details available for each detected attack. |
| **Failure Post-Conditions** | 1. Log file empty if no attacks detected. 2. Log file not found if detection never ran. |

**Typical Course of Events:**

| Step | Actor Action | System Response |
|------|--------------|-----------------|
| 1 | Analyst views attack log table in dashboard | Dashboard displays recent attacks in table format |
| 2 | Analyst views logs/detections.log file | File system presents log entries |
| 3 | Analyst reviews timestamp, type, source, destination | Log provides structured information |
| 4 | Analyst identifies attack patterns | Historical data enables pattern analysis |

**Alternative Courses:**

| Condition | System Response |
|-----------|-----------------|
| No attacks detected | Dashboard shows "No recent attacks detected" |
| Log file missing | File system returns file not found |
| Log file corrupted | Partial data may be readable |

---

# 5. Non-Functional Requirements

## 5.1 Performance Requirements

| Req ID | Requirement | Metric | Target |
|--------|-------------|--------|--------|
| PR-01 | Flow classification latency | Time from flow completion to classification result | < 100 milliseconds |
| PR-02 | Dashboard refresh rate | Status update frequency | 1 second interval |
| PR-03 | PCAP processing throughput | Flows processed per second | ≥ 1,000 flows/second for feature extraction |
| PR-04 | Model inference time | Time per prediction | < 10 milliseconds per flow |
| PR-05 | Memory usage during training | Peak RAM consumption | < 4 GB for standard dataset |
| PR-06 | Memory usage during detection | Steady-state RAM consumption | < 500 MB |
| PR-07 | Dashboard page load time | Initial page render | < 2 seconds |
| PR-08 | API response time | /api/status endpoint response | < 50 milliseconds |
| PR-09 | Concurrent flow handling | Simultaneous flow analysis | ≥ 100 concurrent flows |
| PR-10 | Log write performance | Attack log write latency | < 10 milliseconds |

## 5.2 Safety Requirements

| Req ID | Requirement | Description |
|--------|-------------|-------------|
| SF-01 | Graceful degradation | System shall continue monitoring even if dashboard becomes unavailable |
| SF-02 | Signal handling | System shall handle SIGINT/SIGTERM for clean shutdown |
| SF-03 | Memory protection | System shall not crash due to memory exhaustion; implement limits on log size |
| SF-04 | Data integrity | Feature extraction shall validate data before model inference |
| SF-05 | Error isolation | Errors in one component shall not crash the entire system |
| SF-06 | Resource cleanup | System shall properly release network interface on shutdown |
| SF-07 | File locking | Log files shall be written atomically to prevent corruption |
| SF-08 | Input validation | Command-line arguments shall be validated before use |

## 5.3 Security Requirements

| Req ID | Requirement | Description |
|--------|-------------|-------------|
| SE-01 | Privilege separation | Only capture module requires root; other components run as user |
| SE-02 | Local access only | Dashboard server binds to localhost by default |
| SE-03 | No sensitive data storage | System does not store packet payloads, only flow metadata |
| SE-04 | Log protection | Detection logs should have restricted file permissions (600) |
| SE-05 | Input sanitization | All file paths and interface names shall be sanitized |
| SE-06 | Dependency verification | Python packages shall be installed from trusted sources |
| SE-07 | Model integrity | Model files shall be validated on load (file existence, format check) |
| SE-08 | No telemetry | System shall not send data to external servers |

## 5.4 Reliability Requirements

| Req ID | Requirement | Metric | Target |
|--------|-------------|--------|--------|
| RL-01 | Detection availability | Uptime percentage | ≥ 99% during operation |
| RL-02 | Capture recovery | Automatic restart on capture failure | Within 5 seconds |
| RL-03 | Model accuracy stability | Classification accuracy over time | Deviation < 5% from training metrics |
| RL-04 | Log durability | Attack log data persistence | No loss on clean shutdown |
| RL-05 | Error rate | System errors per hour of operation | < 1 non-critical error/hour |
| RL-06 | Recovery time | Time to restart from failure | < 30 seconds |
| RL-07 | Dashboard connectivity | Reconnection on network recovery | Within 3 seconds |
| RL-08 | Data consistency | Feature extraction consistency | Identical features for identical flows |

## 5.5 Usability Requirements

| Req ID | Requirement | Description |
|--------|-------------|-------------|
| US-01 | Setup simplicity | Installation via single setup script (setup.sh) |
| US-02 | Clear status indication | Dashboard provides unambiguous SAFE/ATTACK status with visual indicators |
| US-03 | Color coding | Green for safe, red for attack, amber for warnings |
| US-04 | Responsive design | Dashboard usable on desktop and tablet browsers |
| US-05 | Progress feedback | Feature extraction shows progress during processing |
| US-06 | Error messages | All errors include actionable guidance for resolution |
| US-07 | Documentation | README.md provides complete usage instructions |
| US-08 | CLI help | All scripts support --help for usage information |
| US-09 | Statistics visibility | Key metrics (flows, attacks) prominently displayed |
| US-10 | Minimal configuration | System works with default settings after installation |

## 5.6 Supportability Requirements

| Req ID | Requirement | Description |
|--------|-------------|-------------|
| SP-01 | Modular architecture | Separate modules for extraction, training, detection, dashboard |
| SP-02 | Code documentation | All Python functions include docstrings |
| SP-03 | Logging | All components log to standardized log files |
| SP-04 | Configuration externalization | Key parameters accessible via command-line arguments |
| SP-05 | Dependency management | requirements.txt lists all Python dependencies with versions |
| SP-06 | Version control | All source code tracked in version control |
| SP-07 | Model versioning | Training metrics saved with model for tracking |
| SP-08 | Scalable design | Architecture allows future addition of attack types |
| SP-09 | Test data | Sample data available for system verification |
| SP-10 | Troubleshooting guide | Common issues documented with solutions |

## 5.7 User Documentation

| Document | Purpose | Contents |
|----------|---------|----------|
| **README.md** | Primary user guide | Overview, features, installation, usage, troubleshooting |
| **Inline Comments** | Developer reference | Code explanations in all Python modules |
| **Training Metrics** | Model documentation | Accuracy, precision, recall, F1-score per class |
| **Setup Script** | Installation guide | Step-by-step automated installation |
| **CLI Help** | Command reference | Usage information for all scripts (--help) |
| **Demo Script** | Demonstration guide | FYP demo procedure in README |

---

# 6. References

| Reference ID | Title | Source/Author | Description |
|--------------|-------|---------------|-------------|
| REF-01 | CIC-DDoS2019 Dataset | Canadian Institute for Cybersecurity | Benchmark dataset for DDoS detection research |
| REF-02 | NFStream Documentation | NFStream Project | Network flow analysis library documentation |
| REF-03 | scikit-learn User Guide | scikit-learn developers | Machine learning library documentation |
| REF-04 | Flask Documentation | Pallets Projects | Web framework documentation |
| REF-05 | Random Forest Algorithm | Leo Breiman (2001) | Original Random Forest paper |
| REF-06 | IEEE 830-1998 | IEEE | Recommended Practice for Software Requirements Specifications |
| REF-07 | Python 3 Documentation | Python Software Foundation | Python language reference |
| REF-08 | DDoS Attack Taxonomy | Mirkovic & Reiher (2004) | Classification of DDoS attacks |
| REF-09 | PCAP File Format | Wireshark | Packet capture file format specification |
| REF-10 | Network Flow Analysis | IETF RFC 7011 | IPFIX specification for flow-based monitoring |

---

**Document End**

*This SRS document is prepared for ThreatGuard-AI, a Final Year Project for educational purposes.*
