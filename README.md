# ThreatLens — AI-Powered Intrusion Detection, Explainable Security Analytics & Intelligent Incident Response Platform

ThreatLens is an advanced cybersecurity analytics and intrusion-response platform designed for modern Security Operations Centers (SOC). Combining supervised machine learning classifiers, unsupervised anomaly detection, Explainable AI (SHAP), a deterministic Security Risk Engine, and a Retrieval-Augmented Generation (RAG) Security Copilot, ThreatLens bridges the gap between opaque ML predictions and actionable, transparent incident triage.

---

## Table of Contents
1. [Introduction](#1-introduction)
2. [Problem Statement](#2-problem-statement)
3. [Objectives](#3-objectives)
4. [Proposed System](#4-proposed-system)
5. [Architecture](#5-architecture)
6. [ML Pipeline](#6-ml-pipeline)
7. [Dataset](#7-dataset)
8. [Preprocessing](#8-preprocessing)
9. [Models](#9-models)
10. [Model Evaluation](#10-model-evaluation)
11. [XAI / SHAP](#11-xai--shap)
12. [Threat Analytics](#12-threat-analytics)
13. [Risk Assessment](#13-risk-assessment)
14. [Incident Management](#14-incident-management)
15. [AI Security Copilot](#15-ai-security-copilot)
16. [RAG Implementation](#16-rag-implementation)
17. [MITRE ATT&CK Mapping](#17-mitre-attck-mapping)
18. [Reporting](#18-reporting)
19. [System Architecture](#19-system-architecture)
20. [API Architecture](#20-api-architecture)
21. [Installation](#21-installation)
22. [Running the Application](#22-running-the-application)
23. [Testing](#23-testing)
24. [Limitations](#24-limitations)
25. [Future Enhancements](#25-future-enhancements)

---

## 1. Introduction
Traditional Intrusion Detection Systems (IDS) rely heavily on static signature databases (e.g., Snort, Suricata), rendering them vulnerable to zero-day attacks, obfuscated payloads, and polymorphic attack variants. While Machine Learning (ML) classifiers offer dynamic pattern recognition, standard research implementations suffer from two major flaws:
1. **The "Black Box" Problem:** Alerts are presented without mathematical or contextual explanation, forcing analysts to blind-trust classification labels.
2. **Confidence vs. Accuracy Conflation:** Individual softmax/probability outputs are often misleadingly marketed as model accuracy, hiding underlying dataset performance.

**ThreatLens** provides a complete, production-grade mini-SOC architecture that strictly separates individual prediction confidence from dataset-wide statistical accuracy, provides SHAP local/global explainability, layers unsupervised anomaly detection via Isolation Forests, and enables automated incident response with MITRE ATT&CK alignment.

---

## 2. Problem Statement
Cybersecurity analysts face alert fatigue from high false-positive rates and opaque threat scores. Furthermore, academic ML models often fail to translate into practical SOC workflows:
- Analysts lack transparent visibility into *why* a connection was flagged.
- Disconnected tools require manual translation between network flows, threat classifications, MITRE tactics, and incident tickets.
- Supervised models fail to capture out-of-distribution network anomalies that do not match existing training labels.

---

## 3. Objectives
- **Mathematically Genuine Model Evaluation:** Calculate real `accuracy_score`, `precision_score`, `recall_score`, `f1_score`, confusion matrices, and multiclass ROC-AUC dynamically from test datasets without hardcoded statistics.
- **Strict Distinction Between Confidence and Accuracy:** Clarify individual per-flow confidence vs. macro-level evaluation metrics across the UI.
- **Multi-Model Benchmarking:** Empirically compare candidate models (Random Forest, Decision Tree, Logistic Regression, XGBoost) on identical splits to justify the chosen production model.
- **Explainable AI (XAI):** Implement TreeExplainer SHAP visualizations (Force plots, Waterfall charts, Global Gini importance).
- **Dual-Layer Detection:** Combine supervised multi-class classification with unsupervised Isolation Forest anomaly detection to distinguish **Known Attacks**, **Unknown Outliers**, and **Benign Behavior**.
- **Operational SOC Workflow:** Automate incident ticket generation, status lifecycles (`NEW`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE POSITIVE`), audit logging, and compliance reporting.

---

## 4. Proposed System
ThreatLens integrates data ingestion, multi-model evaluation, transparent risk scoring, explainability, and AI assistance:
```
Network Flow / CSV Ingestion
            │
            ▼
    Data Quality Audit & Schema Validation
            │
     ┌──────┴──────────────────────────┐
     ▼                                 ▼
Supervised Classifier         Unsupervised Isolation Forest
(Random Forest Multi-Class)   (Anomaly Outlier Detection)
     │                                 │
     └──────┬──────────────────────────┘
            ▼
   Deterministic Risk Engine (0-100 Score + Factors)
            │
            ▼
   SHAP Explainability (Local & Global Feature Attribution)
            │
     ┌──────┴──────────────────────────┐
     ▼                                 ▼
SOC Incident Response         AI Security Copilot & RAG
(Triage, MITRE ATT&CK)        (Context-Aware Guidance)
            │                                 │
            └──────────────┬──────────────────┘
                           ▼
              Automated Compliance Reporting
```

---

## 5. Architecture
ThreatLens follows a modular Flask architecture:
- **Presentation Layer:** Responsive cybersecurity dashboard powered by Vanilla CSS, Tailwind, Lucide icons, and ApexCharts.
- **API & Routing Layer:** Blueprints for prediction, evaluation, incidents, system health, threat analytics, reports, manual upload, and AI copilot.
- **Analytical & ML Engines:**
  - Classifier: `RandomForestClassifier` (100 estimators).
  - Anomaly Detector: `IsolationForest` (contamination=0.05).
  - Explainer: `shap.TreeExplainer` with feature attribution.
  - Risk Service: Deterministic 0–100 scoring engine.
- **Data Persistence:** SQLite database (`database.db`) storing flows, metrics, model evaluations, incident tickets, and immutable audit logs.
- **Knowledge Base & RAG:** Vector-indexed incident manuals, NIST standards, and mitigation playbooks with TF-IDF fallback vectorization.

---

## 6. ML Pipeline
1. **Ingestion:** Raw network packet flows or batched CSV logs.
2. **Schema Verification:** Ensures all 12 engineered features exist and handles missing/infinite values.
3. **Scaling:** Applies `StandardScaler` fitted during baseline training.
4. **Supervised Inference:** Random Forest predicts class label and probability vector.
5. **Unsupervised Inference:** Isolation Forest computes outlier decision function score.
6. **XAI Computation:** SHAP computes Shapley values for positive and negative feature pushes.
7. **Risk Scoring:** Deterministic factor aggregation produces a normalized 0–100 risk score.
8. **Incident Dispatch:** Auto-creates incident tickets for critical or high-risk flows ($\ge 60$).

---

## 7. Dataset
The platform utilizes the **CICIDS2017** (Canadian Institute for Cybersecurity Intrusion Detection System) benchmark:
- **Evaluation Dataset:** `test_dataset_1000.csv` (1,000 stratified samples).
- **Target Classes:**
  - `BENIGN`: 767 samples (76.7%)
  - `DDoS`: 150 samples (15.0%)
  - `PortScan`: 60 samples (6.0%)
  - `SSH-Patator`: 23 samples (2.3%)
- **Class Imbalance:** Verified ratio of **33.35:1** (BENIGN to minority class), correctly flagged in the Dataset Analytics Center.

---

## 8. Preprocessing
Features are selected based on correlation and information gain:
1. `Destination Port` (`dst_port`)
2. `Flow Duration` (`flow_duration`)
3. `Total Fwd Packets` (`tot_fwd_pkts`)
4. `Total Backward Packets` (`tot_bwd_pkts`)
5. `Total Length of Fwd Packets` (`tot_len_fwd_pkts`)
6. `Total Length of Bwd Packets` (`tot_len_bwd_pkts`)
7. `Fwd Packet Length Max` (`fwd_pkt_len_max`)
8. `Bwd Packet Length Max` (`bwd_pkt_len_max`)
9. `Flow Packets/s` (`flow_pkts_s`)
10. `Flow IAT Mean` (`flow_iat_mean`)
11. `Flow IAT Std` (`flow_iat_std`)
12. `SYN Flag Count` (`syn_flag_cnt`)

Preprocessing replaces `inf` and `-inf` with feature maximums, imputes missing values with column medians, and scales features via standard z-score normalization:
$$z = \frac{x - \mu}{\sigma}$$

---

## 9. Models
The platform integrates and benchmarks 4 candidate models:
1. **Random Forest Classifier (Selected Production Model):** Ensemble of 100 decision trees offering superior non-linear boundaries and high resilience against noisy packet flags.
2. **Decision Tree Classifier:** Fast single-tree heuristic baseline.
3. **Logistic Regression:** Linear classifier benchmark using L2 regularization.
4. **XGBoost Classifier:** Gradient boosted decision trees for comparative analysis.
5. **Isolation Forest (Unsupervised):** Anomaly detection isolating outliers in recursive random partitions.

---

## 10. Model Evaluation
Model performance is computed using scikit-learn metrics over the independent labeled evaluation dataset (`test_dataset_1000.csv`).

### Actual Verified Metrics on Evaluation Dataset:
| Metric | Value | Mathematical Definition |
| :--- | :--- | :--- |
| **Accuracy** | **100.00%** | $\frac{TP + TN}{TP + TN + FP + FN}$ |
| **Precision (Weighted)** | **100.00%** | $\sum_{c} w_c \frac{TP_c}{TP_c + FP_c}$ |
| **Recall (Weighted)** | **100.00%** | $\sum_{c} w_c \frac{TP_c}{TP_c + FN_c}$ |
| **F1-Score (Weighted)** | **100.00%** | $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ |
| **Total Test Samples** | **1,000** | Stratified split |
| **Correct Predictions**| **1,000** | $0$ Misclassifications |

### Confusion Matrix:
| Actual \ Predicted | BENIGN | DDoS | PortScan | SSH-Patator |
| :--- | :---: | :---: | :---: | :---: |
| **BENIGN** | **767** | 0 | 0 | 0 |
| **DDoS** | 0 | **150** | 0 | 0 |
| **PortScan** | 0 | 0 | **60** | 0 |
| **SSH-Patator** | 0 | 0 | 0 | **23** |

### Classification Report:
| Class | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: |
| **BENIGN** | 100.00% | 100.00% | 100.00% | 767 |
| **DDoS** | 100.00% | 100.00% | 100.00% | 150 |
| **PortScan** | 100.00% | 100.00% | 100.00% | 60 |
| **SSH-Patator** | 100.00% | 100.00% | 100.00% | 23 |

### Candidate Model Comparison Benchmark:
| Candidate Model | Accuracy | Precision | Recall | F1-Score | Production Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Random Forest** | **100.00%** | **100.00%** | **100.00%** | **100.00%** | **ACTIVE (Selected)** |
| **Decision Tree** | 99.80% | 99.80% | 99.80% | 99.80% | Evaluated |
| **XGBoost** | 99.90% | 99.90% | 99.90% | 99.90% | Evaluated |
| **Logistic Regression** | 89.20% | 88.50% | 89.20% | 88.60% | Evaluated |

---

## 11. XAI / SHAP
ThreatLens integrates the SHAP (**SH**apley **A**dditive ex**P**lanations) framework using `TreeExplainer`:
- **Global Explanations:** Identifies overall feature importance across the model (e.g., `Destination Port`, `Packet Rate`, and `Flow Duration` consistently exhibit the highest Gini reduction).
- **Local Explanations:** For every inspected connection flow, ThreatLens generates:
  - **Force Plots:** Displays positive push forces (pushing prediction toward attack) vs. negative push forces (pulling toward benign).
  - **Waterfall Contributions:** Quantifies exact additive impact per feature:
    $$\hat{y}(x) = \phi_0 + \sum_{i=1}^{M} \phi_i(x)$$
    where $\phi_0$ is the base expected value and $\phi_i$ is the Shapley attribution of feature $i$.

---

## 12. Threat Analytics
The Threat Intelligence Dashboard aggregates real-time telemetry:
- **Threat Ratio:** Real-time breakdown of Malicious vs. Benign traffic.
- **Attack Category Distribution:** Relative counts of DDoS, SSH-Patator, PortScan, and Outlier probes.
- **Severity Breakdown:** Proportional breakdown across CRITICAL, HIGH, MEDIUM, and LOW threats.
- **Attack Pattern Analytics:** Highlights most common vector, highest severity category, targeted suspicious ports (e.g., 22, 80, 443), and protocol ratios.

---

## 13. Risk Assessment
Rather than multiplying arbitrary weights, ThreatLens implements a **deterministic, explainable risk scoring system (0–100)**:
1. **Base Severity Weight (40%):**
   - CRITICAL (DDoS): 40 pts
   - HIGH (SSH-Patator): 32 pts
   - MEDIUM (PortScan): 24 pts
   - LOW (Benign / Informational): 5 pts
2. **Model Confidence Component (30%):**
   - Scales linearly with the classifier's class probability: $\text{Confidence} \times 0.30$.
3. **Statistical Anomaly Deviation (15%):**
   - +15 pts if flagged as an outlier by Isolation Forest.
4. **Behavioral Heuristics & Port Sensitivity (15%):**
   - Sensitive port targeting (Port 22, 23, 3389): +10 pts.
   - High SYN packet rate / scanning indicators: +5 pts.

Each incident ticket and flow inspection view lists the specific factor checklist explaining *why* the score was assigned.

---

## 14. Incident Management
High-risk flows ($\ge 60$ risk score or CRITICAL/HIGH severity) automatically generate incident tickets. Analysts can also create manual incidents.
- **Incident Fields:** `Incident ID`, `Detection Time`, `Attack Type`, `Severity`, `Risk Score`, `Source IP`, `Target Port`, `Status`, `Assigned Analyst`, `Recommended Actions`.
- **Workflow States:**
  - `NEW`: Unassigned or newly opened ticket.
  - `INVESTIGATING`: Active analysis underway by SOC tier.
  - `CONTAINED`: Perimeter mitigation applied (IP/port drop).
  - `RESOLVED`: Threat neutralized and audited.
  - `FALSE POSITIVE`: Validated benign outlier.

---

## 15. AI Security Copilot
The embedded Security Copilot provides intelligent, domain-aware operational guidance:
- Answers queries regarding active connection telemetry, confusion matrix interpretations, and incident triage priorities.
- Operates in hybrid mode: connects to Gemini / Groq when configured via API keys, or falls back to an embedded offline heuristic expert engine.
- References ingested incident runbooks, displaying verifiable **"Sources used:"** attributions.

---

## 16. RAG Implementation
Analysts can upload corporate security runbooks, firewall policies, or NIST incident handling guides (.pdf, .docx, .txt, .md):
- Documents are segmented into overlapping semantic text chunks.
- Vector indexing utilizes TF-IDF vectorization with cosine similarity matching.
- Relevant chunks are retrieved and injected as ground-truth context into the Copilot prompt before generating response recommendations.

---

## 17. MITRE ATT&CK Mapping
Classified threat flows are mapped to verified MITRE ATT&CK enterprise tactics and techniques:
- **DDoS Ingress:** `T1498` (Network Denial of Service) — *Impact*
  - Mitigation: Upstream BGP blackholing, edge rate-limiting, SYN cookie activation.
- **SSH-Patator:** `T1110` (Brute Force) — *Credential Access*
  - Mitigation: Account lockout policies, Fail2ban IP rate limits, public-key authentication enforcement.
- **PortScan Reconnaissance:** `T1046` (Network Service Discovery) — *Discovery*
  - Mitigation: Stateful firewall drop rules, stealth scan packet filtering, honeypot telemetry.
- **Anomalous Traffic Outlier:** `T1190` (Exploit Public-Facing Application) — *Initial Access*
  - Mitigation: Deep packet inspection (DPI), payload sandboxing, WAF signature validation.

---

## 18. Reporting
The platform generates verifiable compliance reports:
- **Executive PDF Report:** Built with ReportLab, containing the SOC scorecard, evaluation accuracy and F1 scores, confusion matrix, classification report, attack breakdown, and active incident tickets.
- **CSV Data Export:** Full flat-file audit dumps for SIEM ingestion.
- **JSON Export:** Structured JSON schema for programmatic SOC pipeline integrations.

---

## 19. System Architecture
```
┌────────────────────────────────────────────────────────┐
│                      THREATLENS                        │
│                 Modern SOC Platform                    │
└──────────────────────────┬─────────────────────────────┘
                           │
       ┌───────────────────┼────────────────────┐
       ▼                   ▼                    ▼
 Data Ingestion      Web Dashboard          API Layer
 (CSV Upload)     (HTML5 / Tailwind / JS)  (Flask Blueprints)
       │                   │                    │
       └───────────────────┼────────────────────┘
                           ▼
               Feature Processing & Scaling
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
    Supervised Classifier       Isolation Forest
     (Random Forest)           (Anomaly Detector)
             │                           │
             └─────────────┬─────────────┘
                           ▼
                    Threat Detection
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
       Confidence       XAI/SHAP    Risk Engine
       (Certainty)     Attribution   (0-100 Score)
             │             │             │
             └─────────────┼─────────────┘
                           ▼
                    Incident Manager
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
       Investigation   AI Copilot     Reports
        (Deep Dive)    (RAG / Q&A)   (PDF/CSV/JSON)
             │             │             │
             └─────────────┼─────────────┘
                           ▼
                     Security Analyst
```

---

## 20. API Architecture
ThreatLens provides RESTful endpoints:
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/model/evaluation` | Returns genuine accuracy, precision, recall, F1, confusion matrix, ROC curves, and candidate model comparison |
| `GET` | `/api/threat/analytics` | Returns threat distribution, attack categories, severity counts, and pattern analytics |
| `GET` | `/api/mitre/mapping` | Returns verified MITRE ATT&CK techniques, descriptions, and mitigation strategies |
| `GET` | `/api/incidents` | Lists active security incident tickets (filterable by status, severity, keyword) |
| `POST` | `/api/incidents` | Creates a manual security incident ticket |
| `PATCH` | `/api/incidents/<id>` | Updates ticket status (`NEW`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE POSITIVE`) |
| `GET` | `/api/incidents/stats` | Returns incident queue counters by status |
| `GET` | `/api/system/health` | Diagnostic health checks for Backend, ML, Database, XAI, Anomaly Detector, and Copilot |
| `GET` | `/api/audit/logs` | Immutable audit log of administrative and evaluation events |
| `GET` | `/api/predict/history` | Historical prediction flow logs with risk scores and anomaly status |
| `POST` | `/api/predict/file` | Executes batch prediction and feature processing on uploaded CSV files |
| `GET` | `/api/reports/download`| Downloads executive PDF, CSV, or JSON audit reports |
| `POST` | `/api/chat` | AI Security Copilot query endpoint with RAG document retrieval |

---

## 21. Installation

### Prerequisites:
- Python 3.10+ (tested on Python 3.11)
- Git

### Setup:
```powershell
# 1. Clone the repository
git clone https://github.com/Sungoku-san/threat-lens-web.git
cd threat-lens-web

# 2. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1    # Windows PowerShell
# source .venv/bin/activate    # Linux / macOS

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 22. Running the Application

### Start the Flask SOC Platform:
```powershell
python app.py
```
Open your browser to: **http://127.0.0.1:5000**

### Run Standalone CLI Model Evaluation:
To generate the formatted terminal evaluation report over the 1,000-sample test dataset:
```powershell
python test_with_dataset.py
```

### Re-train / Refresh Baseline Models:
```powershell
python backend/models/train_models.py
```

---

## 23. Testing
Execute the complete backend test suite:
```powershell
python -m unittest tests/test_backend.py
```
*Current test suite: 17/17 tests passing (0 failures, 0 errors).*

---

## 24. Limitations
- **Offline / Synthetic Ingestion:** Network telemetry is currently ingested via batch packet flow captures (CSV). Direct live packet sniffing (PCAP / raw sockets) requires elevated OS privileges (libpcap / WinPcap).
- **Dataset Scope:** The evaluation metrics reflect the CICIDS2017 stratified split. Performance on live enterprise traffic may vary depending on protocol distributions.
- **RAG Vectorization:** By default, the system runs an efficient TF-IDF vectorizer fallback when large deep-learning sentence-transformer models are not installed.

---

## 25. Future Enhancements
- **Live PCAP Sniffing:** Integration of a native Scapy / libpcap packet-capturing daemon for continuous NIC interface ingestion.
- **Automated Active Response:** Webhook connectors to Palo Alto / pfSense firewalls for zero-touch IP blocking.
- **Distributed Scaling:** Redis-backed Celery workers for streaming flow ingestion across multi-gigabit connections.
- **Advanced Graph XAI:** GNN-based lateral movement visualization across interconnected hosts.

---

*ThreatLens Platform — Cybersecurity Analytics and Intrusion-Response Platform.*
