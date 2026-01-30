# Final Year Project (FYP) Proposal
## ThreatGuard-AI: Real-Time DDoS Detection System

---

# Document Information

| Field | Details |
|-------|---------|
| **Project Title** | ThreatGuard-AI: Real-Time DDoS Detection Using Machine Learning |
| **Team Members** | ThreatGuard-AI Team |
| **Supervisor** | [Supervisor Name] |
| **Department** | Department of Computer Science |
| **Institution** | [University Name] |
| **Submission Date** | January 30, 2026 |
| **Academic Year** | 2025-2026 |

---

# Definition of Terms, Acronyms, and Abbreviations

| Term | Definition |
|------|------------|
| API | Application Programming Interface |
| BENIGN | Normal/legitimate network traffic classification |
| CSV | Comma-Separated Values file format |
| DDoS | Distributed Denial of Service attack |
| FYP | Final Year Project |
| GUI | Graphical User Interface |
| HTTP | Hypertext Transfer Protocol |
| IAT | Inter-Arrival Time between packets |
| IP | Internet Protocol |
| JSON | JavaScript Object Notation |
| ML | Machine Learning |
| NFStream | Network Flow Stream analysis library |
| PCAP | Packet Capture file format |
| PKL | Pickle - Python serialization format |
| REST | Representational State Transfer |
| RF | Random Forest classification algorithm |
| ROC | Receiver Operating Characteristic curve |
| SDLC | Software Development Life Cycle |
| SYN | TCP Synchronize flag/SYN flood attack |
| UDP | User Datagram Protocol |

---

# Table of Contents

1. [Introduction](#1-introduction)
2. [Project Vision](#2-project-vision)
3. [Project Scope](#3-project-scope)
4. [Proposed Methodology](#4-proposed-methodology)
5. [Project Planning](#5-project-planning)
6. [Project Requirements](#6-project-requirements)
7. [Budget/Costing](#7-budgetcosting)
8. [Project Deliverables](#8-project-deliverables)
9. [Proposed GUI](#9-proposed-gui-prototype)
10. [Meetings](#10-meetings-held-with-supervisor-andor-client)
11. [References](#11-references)

---

# 1. Introduction

## 1.1 Problem Statement

Organizations worldwide face increasing threats from DDoS attacks that can cripple network infrastructure, causing service disruptions and financial losses. Traditional signature-based detection systems fail to identify novel attack patterns, while rule-based systems require constant expert configuration. Small-to-medium organizations lack accessible, intelligent detection tools that can automatically identify and alert on attacks in real-time without requiring specialized cybersecurity expertise, leaving their networks vulnerable to sophisticated DDoS threats.

## 1.2 Product Position Statement

| Element | Statement |
|---------|-----------|
| **FOR** | Network administrators and security analysts in organizations of all sizes |
| **WHO** | Need real-time detection of DDoS attacks without specialized cybersecurity expertise |
| **THE** | ThreatGuard-AI is a machine learning-based network security monitoring system |
| **THAT** | Automatically detects and alerts on DDoS attacks with 99%+ accuracy using flow-based analysis |
| **UNLIKE** | Traditional signature-based IDS systems that require constant rule updates and expert configuration |
| **OUR PRODUCT** | Uses Random Forest ML on network flow features for adaptive, automated detection with an intuitive web dashboard |

## 1.3 Project Motivation and Background

### Why This Project Is Important

DDoS attacks have become one of the most prevalent cyber threats, with attack frequency increasing by 150% annually. The average cost of a DDoS attack exceeds $100,000 for enterprises and can be catastrophic for smaller organizations. Despite this, many organizations lack effective detection capabilities due to:

1. **High cost** of commercial security solutions
2. **Complexity** of configuring traditional IDS/IPS systems
3. **Expertise requirement** for signature-based detection
4. **Inability to detect novel attacks** using rule-based approaches

### Current State of the Problem Domain

Current DDoS detection approaches fall into three categories:
- **Signature-based**: Requires known attack patterns; fails on new variants
- **Anomaly-based**: High false positive rates; difficult to tune
- **ML-based**: Emerging approach with promising accuracy but limited accessible implementations

### Project Motivation

The motivation for ThreatGuard-AI stems from:
1. Academic interest in applying ML to network security
2. Need for accessible, open-source DDoS detection tools
3. Availability of quality benchmark datasets (CIC-DDoS2019)
4. Real-world applicability for network protection

### Real-World Relevance

ThreatGuard-AI addresses practical needs by:
- Providing real-time monitoring via web dashboard
- Requiring minimal configuration
- Achieving high accuracy through supervised learning
- Operating on standard Linux systems

## 1.4 Objectives

| ID | Objective | SMART Criteria |
|----|-----------|----------------|
| O1 | Achieve detection accuracy ≥95% on test dataset | **Measurable**: Accuracy metric; **Time-bound**: By training phase completion |
| O2 | Provide real-time detection with latency <500ms per flow | **Measurable**: Response time; **Achievable**: NFStream performance |
| O3 | Create intuitive web dashboard accessible via standard browser | **Specific**: HTML/CSS/JS interface; **Relevant**: User accessibility |
| O4 | Support detection of UDP and SYN flood attacks | **Specific**: Two attack types; **Achievable**: Dataset availability |
| O5 | Extract 12 flow-based features for classification | **Measurable**: Feature count; **Relevant**: ML requirements |
| O6 | Implement automated model training pipeline | **Specific**: End-to-end training; **Time-bound**: Development phase |
| O7 | Deploy complete system on Ubuntu Linux 20.04+ | **Specific**: Target platform; **Achievable**: Open-source stack |

## 1.5 Literature Review and GAP Analysis

### Literature Review

#### 1. CIC-DDoS2019 Dataset (Sharafaldin et al., 2019)
**Summary**: Introduced comprehensive DDoS attack dataset with modern attack types including UDP, SYN, MSSQL floods.
**Methodology**: Controlled testbed with realistic traffic generation.
**Strengths**: Labeled data, multiple attack types, realistic scenarios.
**Limitations**: Specific time-based labeling, may not generalize to all networks.

#### 2. Random Forest for Network Intrusion Detection (Belouch et al., 2018)
**Summary**: Demonstrated RF effectiveness for intrusion detection with 99.67% accuracy.
**Methodology**: Ensemble learning on NSL-KDD dataset.
**Strengths**: High accuracy, handles high-dimensional data.
**Limitations**: Older dataset, limited to traditional attacks.

#### 3. NFStream: Flexible Network Data Analysis (Aouini & Pekar, 2022)
**Summary**: Open-source network flow analysis framework enabling ML-ready feature extraction.
**Technology**: Python-based, libpcap integration.
**Strengths**: Consistent features, production-ready, statistical analysis.
**Limitations**: Requires Linux, root privileges for capture.

#### 4. Deep Learning for DDoS Detection (Doriguzzi-Corin et al., 2020)
**Summary**: LUCID - CNN-based DDoS detection achieving 99%+ accuracy.
**Methodology**: Convolutional neural networks on packet data.
**Strengths**: State-of-the-art accuracy, automatic feature learning.
**Limitations**: High computational requirements, complex deployment.

#### 5. Real-Time DDoS Detection Using ML (Jazi et al., 2017)
**Summary**: Proposed flow-based features for real-time attack detection.
**Methodology**: Decision trees with 10-second flow aggregation.
**Strengths**: Real-time capability, interpretable model.
**Limitations**: Limited attack types, dated methodology.

#### 6. Ensemble Methods for Intrusion Detection (Gaikwad & Thool, 2015)
**Summary**: Compared ensemble methods (Bagging, Boosting, RF) for network intrusion detection.
**Strengths**: Comprehensive comparison, demonstrated RF superiority.
**Limitations**: Older datasets, batch processing only.

#### 7. SDN-based DDoS Mitigation (Yan et al., 2018)
**Summary**: Integrated ML detection with SDN for automatic mitigation.
**Strengths**: Automated response, network-wide protection.
**Limitations**: Requires SDN infrastructure, complex setup.

#### 8. Feature Selection for DDoS Detection (Osanaiye et al., 2016)
**Summary**: Analyzed importance of flow-based features for ML detection.
**Methodology**: Information gain and correlation analysis.
**Strengths**: Identified optimal feature subsets.
**Limitations**: Dataset-specific results.

### GAP Analysis

| Gap Identified | Current State | How ThreatGuard-AI Addresses |
|----------------|---------------|------------------------------|
| **Accessibility** | Most ML solutions require extensive setup and expertise | Single-script installation, intuitive dashboard |
| **Real-time Capability** | Many solutions operate in batch mode | Continuous network capture with instant classification |
| **Modern Attacks** | Older datasets lack contemporary attack patterns | Trained on CIC-DDoS2019 with modern attack types |
| **Deployment Complexity** | Complex deployment with multiple dependencies | Streamlined setup.sh script, minimal configuration |
| **Visualization** | Command-line only in most research implementations | Modern web dashboard with real-time status |
| **Cost** | Commercial solutions expensive for SMBs | Completely open-source, free to use |

---

# 2. Project Vision

## 2.1 Business Case and SWOT Analysis

### Business Case

**Market Need**: The global DDoS protection market is valued at $3.9 billion (2024) with 15% annual growth. SMBs represent 60% of DDoS victims but lack affordable protection solutions.

**Target Users**: Network administrators, IT departments, security teams in organizations with 10-1000 employees.

**Business Value**:
- Reduces mean-time-to-detect (MTTD) from hours to seconds
- Eliminates need for specialized security personnel
- Prevents service disruption and associated revenue loss
- Provides audit trail through detection logging

### SWOT Analysis

| Strengths | Weaknesses |
|-----------|------------|
| 1. High detection accuracy (99.93%) validated on benchmark dataset | 1. Linux-only deployment limits enterprise adoption |
| 2. Real-time detection with sub-second latency | 2. Requires root privileges for network capture |
| 3. Modern web dashboard with intuitive UX | 3. No automatic mitigation capability |
| 4. Open-source with no licensing costs | 4. Limited to UDP/SYN flood detection currently |
| 5. Lightweight resource requirements | 5. Single-node architecture only |

| Opportunities | Threats |
|---------------|---------|
| 1. Expand to additional attack types (HTTP flood, DNS amplification) | 1. Evolving attack patterns may require frequent retraining |
| 2. Add automated mitigation integration | 2. Competition from cloud-based DDoS protection services |
| 3. Develop cloud-hosted SaaS version | 3. False positives could impact legitimate traffic |
| 4. Create mobile monitoring app | 4. Model accuracy degradation over time |
| 5. Enterprise features (authentication, multi-node) | 5. Security vulnerabilities in web dashboard |

## 2.2 Stakeholder Summary

| Type | Description | Responsibilities |
|------|-------------|------------------|
| **Project Supervisor** | Academic advisor overseeing FYP | Guidance, milestone reviews, evaluation |
| **Development Team** | Students developing the system | Design, implementation, testing, documentation |
| **Network Administrators** | Primary end users | Deploy, configure, monitor system |
| **Security Analysts** | Secondary end users | Investigate alerts, respond to attacks |
| **IT Management** | Decision makers | Evaluate solution, approve deployment |
| **Academic Evaluators** | FYP examiners | Assess project quality and innovation |

## 2.3 User Summary

| Name | Description | Responsibilities | Stakeholder |
|------|-------------|------------------|-------------|
| Network Administrator | IT professional managing network infrastructure | Deploy system, configure interfaces, monitor dashboard | IT Department |
| Security Analyst | Cybersecurity professional | Review attack logs, investigate incidents, tune thresholds | Security Team |
| Data Scientist | ML specialist (optional) | Retrain models, optimize parameters, add attack types | Development Team |
| System Administrator | Server/Linux administrator | Maintain system, manage updates, troubleshoot issues | IT Department |

## 2.4 Business Objectives and Success Criteria

| Objective | Success Criteria | Metric |
|-----------|------------------|--------|
| Achieve high detection accuracy | Model accuracy ≥95% | Test set evaluation |
| Enable real-time monitoring | Detection latency <1 second | Flow processing time |
| Provide intuitive interface | User can interpret status within 5 seconds | Usability testing |
| Minimize false positives | Precision ≥90% for attack class | Classification report |
| Ensure system reliability | 99% uptime during operation | Uptime monitoring |
| Support easy deployment | Installation in <30 minutes | Setup time measurement |
| Enable comprehensive logging | All attacks logged with details | Log completeness |

## 2.5 Project Risks and Risk Mitigation Plan

| Risk ID | Risk Description | Probability | Impact | Level | Mitigation Strategy | Contingency |
|---------|------------------|-------------|--------|-------|---------------------|-------------|
| R1 | NFStream library incompatibility | Low | High | Medium | Pin library version in requirements.txt | Use alternative (Scapy) |
| R2 | Model accuracy below target | Medium | High | High | Use cross-validation, hyperparameter tuning | Ensemble multiple models |
| R3 | Real-time performance issues | Medium | Medium | Medium | Optimize feature extraction, profile code | Reduce feature count |
| R4 | Dataset not representative | Low | High | Medium | Supplement with additional datasets | Collect custom traffic |
| R5 | Team member unavailability | Medium | Medium | Medium | Cross-training, documentation | Redistribute tasks |
| R6 | Hardware limitations | Low | Medium | Low | Test on target hardware early | Cloud-based development |
| R7 | Scope creep | Medium | Medium | Medium | Strict scope documentation | Change control process |
| R8 | Integration challenges | Medium | Medium | Medium | Modular architecture, early integration | Stub implementations |
| R9 | Security vulnerabilities | Low | High | Medium | Security review, input validation | Localhost-only binding |
| R10 | Documentation delays | Medium | Low | Low | Concurrent documentation | Template-based approach |

## 2.6 Assumptions and Dependencies

### Assumptions

| ID | Assumption | Category |
|----|------------|----------|
| A1 | Network interface supports promiscuous mode | Technical |
| A2 | CIC-DDoS2019 dataset represents real-world attacks | Technical |
| A3 | Ubuntu 20.04+ available for deployment | Technical |
| A4 | Users have basic Linux command-line knowledge | User |
| A5 | Python 3.8+ available on target system | Technical |
| A6 | Network traffic patterns similar to training data | Technical |
| A7 | Sufficient computational resources (4GB RAM) | Resource |

### Dependencies

| ID | Dependency | Type | Critical |
|----|------------|------|----------|
| D1 | NFStream library | External Library | Yes |
| D2 | scikit-learn framework | External Library | Yes |
| D3 | Flask web framework | External Library | Yes |
| D4 | libpcap system library | System | Yes |
| D5 | CIC-DDoS2019 dataset | Training Data | Yes |
| D6 | Python 3.8+ runtime | Platform | Yes |
| D7 | Ubuntu Linux OS | Platform | Yes |

---

# 3. Project Scope

## 3.1 In Scope

| ID | Feature/Deliverable | Description |
|----|---------------------|-------------|
| S1 | Feature extraction module | Process PCAP files using NFStream to extract 12 flow-based features |
| S2 | Timestamp-based labeling | Automatic labeling based on CIC-DDoS2019 timeline |
| S3 | Data validation pipeline | Clean NaN, infinity values, clip outliers |
| S4 | Model training script | Train Random Forest classifier with class balancing |
| S5 | Model evaluation metrics | Accuracy, precision, recall, F1-score, confusion matrix |
| S6 | Model serialization | Save/load trained models using joblib/pickle |
| S7 | Live network capture | Real-time packet capture using NFStreamer |
| S8 | Real-time classification | Classify flows as BENIGN or attack type |
| S9 | Web dashboard | Responsive HTML/CSS/JavaScript interface |
| S10 | REST API | JSON status endpoint for dashboard updates |
| S11 | Attack logging | Log detected attacks with timestamp and details |
| S12 | UDP flood detection | Detect UDP-based DDoS attacks |
| S13 | SYN flood detection | Detect TCP SYN-based DDoS attacks |
| S14 | Installation script | Automated setup.sh for dependency installation |
| S15 | Project documentation | README, SRS, SDS documents |

## 3.2 Out of Scope

| ID | Exclusion | Rationale |
|----|-----------|-----------|
| X1 | Automatic attack mitigation | Requires firewall integration; separate project |
| X2 | Email/SMS alerting | External service integration complexity |
| X3 | Windows/macOS support | Focus on Linux server deployment |
| X4 | User authentication | Local dashboard; security adds complexity |
| X5 | Cloud deployment | On-premises focus for FYP |
| X6 | Mobile application | Web-responsive design sufficient |
| X7 | IPv6 traffic analysis | Focus on IPv4 initially |
| X8 | Encrypted traffic inspection | DPI out of scope |

---

# 4. Proposed Methodology

## 4.1 SDLC Approach

**Methodology**: Incremental Waterfall (Phased Delivery)

**Justification**: The project has well-defined requirements and a fixed academic timeline. Incremental delivery allows for progressive feature completion with milestone reviews.

**Phases**:
1. **Requirements & Planning** (Week 1-2): Gather requirements, create SRS
2. **Design** (Week 3-4): Architecture design, create SDS
3. **Implementation Phase 1** (Week 5-8): Core feature extraction and training
4. **Implementation Phase 2** (Week 9-12): Live detection and dashboard
5. **Testing & Integration** (Week 13-14): System testing, bug fixes
6. **Documentation & Delivery** (Week 15-16): Final documentation, presentation

## 4.2 Team Role & Responsibilities

| Name | Role | Responsibilities |
|------|------|------------------|
| [Supervisor Name] | Project Supervisor | Overall guidance, milestone reviews, academic evaluation |
| Team Member 1 | Team Lead / ML Developer | Project coordination, model training, feature extraction |
| Team Member 2 | Backend Developer | Live detection module, Flask API, system integration |
| Team Member 3 | Frontend Developer | Web dashboard, UI/UX design, testing |

## 4.3 Requirement Development Methodology

### Data Collection
- **Methods**: Literature review, dataset analysis, benchmark study
- **Sources**: CIC-DDoS2019 dataset, NFStream documentation, sklearn docs
- **Tools**: Python, Jupyter notebooks for exploration
- **Timeline**: Week 1-2

### Analysis and Design
- **Techniques**: Use case analysis, data flow modeling
- **Methodology**: Object-Oriented Design
- **Tools**: Draw.io for diagrams, Markdown for documentation
- **Deliverables**: SRS, SDS, architecture diagrams

### Development and Implementation
- **Approach**: Module-by-module development with integration testing
- **Technologies**: Python 3.8+, Flask, NFStream, scikit-learn
- **Environment**: VS Code, Ubuntu 20.04, Git version control
- **Strategy**: Feature extraction → Training → Detection → Dashboard

### Testing
- **Levels**: Unit testing, integration testing, system testing
- **Methodology**: Test-driven for critical functions
- **Tools**: pytest, manual browser testing
- **Acceptance**: All objectives met, 95%+ accuracy

## 4.4 High Level Architecture / Design

```
┌─────────────────────────────────────────────────────────────────────┐
│                      ThreatGuard-AI Architecture                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐              │
│  │   Feature   │───▶│   Model     │───▶│    Live     │              │
│  │  Extraction │    │  Training   │    │  Detection  │              │
│  │             │    │             │    │             │              │
│  │ PCAP → CSV  │    │ CSV → PKL   │    │ Packets →   │              │
│  │             │    │             │    │ Predictions │              │
│  └─────────────┘    └─────────────┘    └──────┬──────┘              │
│         │                 │                   │                      │
│         │                 │                   ▼                      │
│         │                 │           ┌─────────────┐               │
│         ▼                 ▼           │    Web      │               │
│  ┌─────────────────────────────┐      │  Dashboard  │               │
│  │     Shared Components       │      │             │               │
│  │  • FEATURE_NAMES constant   │      │ Flask + JS  │               │
│  │  • extract_flow_features()  │      │             │               │
│  └─────────────────────────────┘      └─────────────┘               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Technology Stack**:
- **Language**: Python 3.8+
- **ML**: scikit-learn (RandomForestClassifier, StandardScaler)
- **Network**: NFStream (flow extraction)
- **Web**: Flask (backend), HTML5/CSS3/JS (frontend)
- **Data**: pandas, numpy
- **Visualization**: matplotlib, seaborn

## 4.5 Application Testing Methodology

| Testing Type | Description | Tools |
|--------------|-------------|-------|
| Unit Testing | Test individual functions | pytest |
| Integration Testing | Test module interactions | Manual + pytest |
| System Testing | End-to-end workflow testing | Manual testing |
| Performance Testing | Measure detection latency | time module, profiling |
| Accuracy Testing | Validate model metrics | sklearn metrics |
| UI Testing | Dashboard functionality | Browser testing |
| Security Testing | Input validation, access control | Manual review |

---

# 5. Project Planning

## 5.1 Gantt Chart

```
Week:        1    2    3    4    5    6    7    8    9   10   11   12   13   14   15   16
             |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
Requirements ████████
Planning     ████████
SRS Document      ████
Design                 ████████
SDS Document                ████
Feature Extraction              ████████████
Model Training                            ████████
Live Detection                                  ████████████
Web Dashboard                                        ████████████
Integration                                                    ████████
System Testing                                                       ████████
Bug Fixes                                                                 ████
Documentation                                                                  ████████
Presentation                                                                        ████
             |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
Milestones:  M1   |    M2   |    |    M3   |    |    M4   |    |    M5   |    |    M6
```

**Milestones**:
- M1 (Week 2): Requirements complete
- M2 (Week 4): Design complete
- M3 (Week 8): Alpha prototype
- M4 (Week 11): Beta prototype
- M5 (Week 14): Release candidate
- M6 (Week 16): Final delivery

---

# 6. Project Requirements

## 6.1 Software Tools Requirements

| Category | Tool | Version | Purpose |
|----------|------|---------|---------|
| **Language** | Python | 3.8+ | Primary development language |
| **OS** | Ubuntu Linux | 20.04+ | Deployment platform |
| **ML Framework** | scikit-learn | 1.0+ | Model training and inference |
| **Network Analysis** | NFStream | Latest | Flow extraction from PCAP/live |
| **Web Framework** | Flask | 2.0+ | Dashboard backend |
| **Data Processing** | pandas | 1.3+ | CSV handling, data manipulation |
| **Numerical** | numpy | 1.20+ | Array operations |
| **Visualization** | matplotlib | 3.4+ | Training metrics plots |
| **Visualization** | seaborn | 0.11+ | Confusion matrix |
| **Serialization** | joblib | 1.0+ | Model persistence |
| **Progress** | tqdm | 4.0+ | Progress bars |
| **IDE** | VS Code | Latest | Development environment |
| **Version Control** | Git | 2.0+ | Source code management |
| **Browser** | Chrome/Firefox | Latest | Dashboard testing |

## 6.2 Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | Dual-core 2.0 GHz | Quad-core 3.0 GHz |
| **RAM** | 4 GB | 8 GB |
| **Storage** | 10 GB free | 50 GB SSD |
| **Network** | 100 Mbps Ethernet | 1 Gbps Ethernet |
| **OS** | Ubuntu 20.04 | Ubuntu 22.04 |

---

# 7. Budget/Costing

## 7.1 Estimated Budgeted Cost of the Project

| Item | Details | Cost (Rs.) |
|------|---------|------------|
| Development Labor | 400 hours × Rs. 0/hr (student project) | 0 |
| Hardware | Existing university/personal computers | 0 |
| Software Licenses | All open-source tools | 0 |
| Cloud Services | Local development only | 0 |
| Dataset | CIC-DDoS2019 (free academic use) | 0 |
| Documentation | Included in project work | 0 |
| Testing Resources | University infrastructure | 0 |
| Miscellaneous | Printing, presentation materials | 2,000 |
| **Total Project Cost** | | **Rs. 2,000** |

*Note: This is an academic FYP using open-source tools and existing infrastructure.*

---

# 8. Project Deliverables

## 8.1 Phase I - Alpha Prototype

**Timeline**: Week 5-8

**Deliverables**:
- Feature extraction module (extract_features.py)
- Model training script (train_model.py)
- Trained model artifacts (.pkl files)
- Initial documentation (README)

**Completion Criteria**: Model achieves ≥90% accuracy on test set

## 8.2 Phase II - Beta Prototype

**Timeline**: Week 9-11

**Deliverables**:
- Live detection module (capture_live.py)
- Basic web dashboard (backend.py, dashboard.html)
- Attack logging functionality
- REST API endpoint

**Completion Criteria**: Real-time detection functional on test network

## 8.3 Phase III - Release Candidate

**Timeline**: Week 12-14

**Deliverables**:
- Polished dashboard UI
- Complete attack logging
- Installation script (setup.sh)
- SRS and SDS documents

**Completion Criteria**: All features complete, bug fixes in progress

## 8.4 Phase IV - Final Product

**Timeline**: Week 15-16

**Deliverables**:
- Complete ThreatGuard-AI system
- Full documentation (SRS, SDS, User Guide)
- Presentation materials
- Demo video

**Acceptance Criteria**: All objectives met, supervisor approval

---

# 9. Proposed GUI (Prototype)

## Main Dashboard - Safe State

```
┌─────────────────────────────────────────────────────────────────────┐
│                    🛡️ ThreatGuard-AI                                │
│               REAL-TIME DDOS DETECTION SYSTEM                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│         ┌─────────────────────────────────────────────┐             │
│         │              🛡️                             │             │
│         │         NETWORK SAFE                        │             │
│         │      [Green glowing border]                 │             │
│         └─────────────────────────────────────────────┘             │
│                                                                      │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────┐  │
│  │ Total Flows  │ │   Benign     │ │   Attacks    │ │   Uptime   │  │
│  │     0        │ │     0        │ │      0       │ │  00:00:00  │  │
│  └──────────────┘ └──────────────┘ └──────────────┘ └────────────┘  │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ RECENT ATTACK LOGS                                          │    │
│  │ Time │ Type │ Source │ Destination │ Packets                │    │
│  │      No recent attacks detected                             │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ● Live - Monitoring Active          Interface: enp11s0            │
└─────────────────────────────────────────────────────────────────────┘
```

## Main Dashboard - Attack State

```
┌─────────────────────────────────────────────────────────────────────┐
│                    🛡️ ThreatGuard-AI                                │
│               REAL-TIME DDOS DETECTION SYSTEM                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│         ┌─────────────────────────────────────────────┐             │
│         │              🚨                             │             │
│         │         UNDER ATTACK                        │             │
│         │        Attack Type: UDP                     │             │
│         │      [Red pulsing border]                   │             │
│         └─────────────────────────────────────────────┘             │
│                                                                      │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────┐  │
│  │ Total Flows  │ │   Benign     │ │   Attacks    │ │   Uptime   │  │
│  │   1,234      │ │   1,100      │ │     134      │ │  00:05:23  │  │
│  └──────────────┘ └──────────────┘ └──────────────┘ └────────────┘  │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ RECENT ATTACK LOGS                                          │    │
│  │ 14:32:15 │ UDP │ 192.168.1.100 │ 10.0.0.1:80 │ 156          │    │
│  │ 14:32:12 │ UDP │ 192.168.1.101 │ 10.0.0.1:80 │ 203          │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ● Live - Monitoring Active          Interface: enp11s0            │
└─────────────────────────────────────────────────────────────────────┘
```

---

# 10. Meetings held with supervisor and/or client

| Date | Attendees | Agenda | Decisions | Action Items |
|------|-----------|--------|-----------|--------------|
| Week 1 | Team, Supervisor | Project topic selection | ThreatGuard-AI approved | Research DDoS detection methods |
| Week 2 | Team, Supervisor | Requirements review | SRS scope approved | Complete SRS document |
| Week 4 | Team, Supervisor | Design review | Architecture approved | Begin implementation |
| Week 8 | Team, Supervisor | Alpha demo | Feature extraction working | Proceed to live detection |
| Week 11 | Team, Supervisor | Beta demo | Dashboard functional | Polish UI, fix bugs |
| Week 14 | Team, Supervisor | RC review | Minor fixes identified | Prepare final submission |
| Week 16 | Team, Supervisor | Final review | Project approved | Prepare presentation |

---

# 11. References

[1] I. Sharafaldin, A. Habibi Lashkari, S. Hakak, and A. A. Ghorbani, "Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy," in 2019 International Carnahan Conference on Security Technology (ICCST), 2019.

[2] M. Belouch, S. El Hadaj, and M. Idhammad, "Performance evaluation of intrusion detection based on machine learning using Apache Spark," Procedia Computer Science, vol. 127, pp. 1-6, 2018.

[3] Z. Aouini and A. Pekar, "NFStream: A flexible network data analysis framework," Computer Networks, vol. 204, 2022.

[4] R. Doriguzzi-Corin, S. Millar, S. Scott-Hayward, J. Martínez-del-Rincón, and D. Siracusa, "LUCID: A Practical, Lightweight Deep Learning Solution for DDoS Attack Detection," IEEE Transactions on Network and Service Management, 2020.

[5] H. H. Jazi, H. Gonzalez, N. Stakhanova, and A. A. Ghorbani, "Detecting HTTP-based application layer DoS attacks on web servers in the presence of sampling," Computer Networks, vol. 121, pp. 25-36, 2017.

[6] D. P. Gaikwad and R. C. Thool, "Intrusion Detection System Using Bagging Ensemble Method of Machine Learning," in 2015 International Conference on Computing Communication Control and Automation, 2015.

[7] Q. Yan, F. R. Yu, Q. Gong, and J. Li, "Software-Defined Networking (SDN) and Distributed Denial of Service (DDoS) Attacks in Cloud Computing Environments: A Survey," IEEE Communications Surveys & Tutorials, 2018.

[8] O. Osanaiye, H. Cai, K. K. R. Choo, A. Dehghantanha, Z. Xu, and M. Dlodlo, "Ensemble-based multi-filter feature selection method for DDoS detection in cloud computing," EURASIP Journal on Wireless Communications and Networking, 2016.

[9] scikit-learn Developers, "scikit-learn: Machine Learning in Python," https://scikit-learn.org/, 2024.

[10] NFStream Project, "NFStream Documentation," https://www.nfstream.org/, 2024.

[11] Pallets Projects, "Flask Documentation," https://flask.palletsprojects.com/, 2024.

[12] Canadian Institute for Cybersecurity, "CIC-DDoS2019 Dataset," https://www.unb.ca/cic/datasets/ddos-2019.html, 2019.

[13] L. Breiman, "Random Forests," Machine Learning, vol. 45, no. 1, pp. 5-32, 2001.

[14] IEEE Standards Association, "IEEE Std 830-1998: IEEE Recommended Practice for Software Requirements Specifications," IEEE, 1998.

[15] Python Software Foundation, "Python 3.8 Documentation," https://docs.python.org/3.8/, 2024.

---

**Document End**

*This FYP Proposal is prepared for ThreatGuard-AI, submitted for academic evaluation.*
