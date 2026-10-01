# Product Requirements Document (PRD)

# ThreatLens (CYBERIDS) — AI-Based Intrusion Detection & Explainable Security Operations System

**Document Version:** 1.0.4  
**Date:** September 2026  
**Status:** Approved / Active Production Baseline  
**Product Name:** ThreatLens (CYBERIDS)  
**Classification:** Enterprise Cybersecurity Architecture  
**Author:** AI Engineering & SOC Product Architecture Team  

---

## Table of Contents
1. [Executive Summary & Product Vision](#1-executive-summary--product-vision)
2. [Problem Statement & Market Drivers](#2-problem-statement--market-drivers)
3. [Target User Personas](#3-target-user-personas)
4. [System Architecture & Technology Stack](#4-system-architecture--technology-stack)
5. [Data Specifications & Feature Engineering](#5-data-specifications--feature-engineering)
6. [Machine Learning & Threat Classification Engine](#6-machine-learning--threat-classification-engine)
7. [Explainable AI (XAI) & SHAP Framework](#7-explainable-ai-xai--shap-framework)
8. [Generative AI & RAG Security Copilot](#8-generative-ai--rag-security-copilot)
9. [Functional Requirements (FR-1 to FR-10)](#9-functional-requirements)
10. [Non-Functional Requirements (NFR-1 to NFR-6)](#10-non-functional-requirements)
11. [API Endpoint Interface Specifications](#11-api-endpoint-interface-specifications)
12. [Database Schema & Data Persistence](#12-database-schema--data-persistence)
13. [Incident Response & Remediation Procedures](#13-incident-response--remediation-procedures)
14. [Security, Governance & Compliance](#14-security-governance--compliance)
15. [Testing, Verification & Quality Assurance](#15-testing-verification--quality-assurance)
16. [Release Roadmap & Future Milestones](#16-release-roadmap--future-milestones)

---

## 1. Executive Summary & Product Vision

### 1.1 Mission Statement
**ThreatLens (CYBERIDS)** is a next-generation, enterprise-grade Security Operations Center (SOC) platform designed to bridge the critical divide between high-accuracy machine learning threat detection and human analyst trust. By fusing multi-class statistical classifiers, **Explainable AI (SHAP)** game-theory attribution, and a **Retrieval-Augmented Generation (RAG) Security Copilot**, ThreatLens empowers security teams to identify, interpret, and mitigate sophisticated cyber intrusions in real time.

### 1.2 Core Value Proposition
- **High-Fidelity Intrusion Detection:** Trained on industry-standard network flow benchmarks (CICIDS2017) to classify multi-vector intrusions with >99% empirical accuracy.
- **Demystified "Black-Box" Decisions:** Granular local and global SHAP (SHapley Additive exPlanations) force charts quantify exactly *why* a flow was flagged, highlighting the exact malicious header features.
- **Autonomous RAG Security Copilot:** Grounded by an in-memory vector store, embedded threat intelligence rules, and multi-tier LLM fallback cascades (Groq LLaMA 3.3, Google Gemini 2.5 Flash, Local Ollama, and an Embedded AI Expert System) to provide instant root-cause analysis and executable mitigation commands.
- **Enterprise SOC User Experience:** Built with a cyberpunk glassmorphism aesthetic, real-time ApexCharts telemetry, slide-over forensic drawers, and automated audit report generation (PDF, CSV, JSON).

---

## 2. Problem Statement & Market Drivers

Modern Security Operations Centers face unprecedented operational bottlenecks:
1. **Alert Fatigue & Noise:** Traditional rule-based signature IDS tools (Snort, Suricata) trigger tens of thousands of daily alerts, with false-positive rates frequently exceeding 15–25%.
2. **The "Black-Box" Trust Deficit:** While Deep Learning and Random Forest models can detect novel zero-day attacks, SOC analysts cannot trust a binary "Malicious" score without knowing *which network parameters* caused the anomaly.
3. **Slow Mean Time to Remediate (MTTR):** Junior analysts (Tier 1 SOC) spend an average of 25–40 minutes per critical incident manually correlating IPs, reading firewall manuals, and drafting mitigation syntax.
4. **Disjointed Knowledge Silos:** Standard operating procedures (SOPs), incident response playbooks, and vendor firewall manuals exist in disparate PDF/Word documents rather than directly interacting with the real-time detection stream.

**ThreatLens directly eliminates these friction points** by combining automated multi-class machine learning, instant mathematical explainability, and context-aware conversational AI.

---

## 3. Target User Personas

| Persona | Role | Key Needs & Pain Points | Primary ThreatLens Touchpoints |
| :--- | :--- | :--- | :--- |
| **Alex Rivera** | Tier 1 / Tier 2 SOC Analyst | Overwhelmed by alert volume; needs instant confirmation of attack validity and confidence scores. | Dashboard Overview, Real-Time Detection Table, Attack Details Drawer, SHAP Force Plots. |
| **Maya Lin** | Incident Response & Threat Hunter | Needs raw feature telemetry, packet rates, and immediate executable mitigation syntax (`iptables`, null routing). | Forensic Drawer, SHAP Feature Importance, Remediation Triggers, AI Security Copilot. |
| **David Vance** | Chief Information Security Officer (CISO) | Needs compliance audit trails, executive summaries, false positive metrics, and SLAs. | Cryptographically signed PDF Audit Reports, Model Info & Accuracy KPIs, CSV Data Exports. |
| **Elena Rostova** | Security Data Scientist / ML Engineer | Needs to inspect feature importance weights, evaluate classifier drift, and tune detection thresholds. | Settings Threshold Slider, Global SHAP Importance, Model Retraining Pipelines (`train_model.py`). |

---

## 4. System Architecture & Technology Stack

ThreatLens is engineered using a modular, decoupled architecture adhering to modern clean-code principles:

```
+-----------------------------------------------------------------------------------+
|                            PRESENTATION LAYER (UI)                                |
|  - HTML5 / Vanilla CSS (Tailwind CSS JIT Engine, Glassmorphism design tokens)    |
|  - Dynamic Telemetry: ApexCharts.js (Live Network Traffic, Heatmap, Donut)        |
|  - Typography & Icons: Space Grotesk / Inter Google Fonts, Lucide Icons           |
|  - Responsive Shell: Collapsible Sidebar, Slide-over Drawer, Modal Overlays        |
+-----------------------------------------------------------------------------------+
                                         |
                                    HTTP / JSON
                                         v
+-----------------------------------------------------------------------------------+
|                        APPLICATION LAYER (FLASK 3.0 API)                          |
|  - App Factory (`create_app`) & Config Loader (.env, Vercel Serverless support)   |
|  - Blueprints: `upload_bp`, `prediction_bp`, `dashboard_bp`, `reports_bp`,        |
|                `shap_bp`, `chat_bp`, `document_bp`, `knowledge_bp`, `manual_bp`   |
|  - Input Validation: Werkzeug secure_filename, CSV Schema & Flow Payload Check    |
|  - Structured Logging: Threaded Timestamps & Component Tracing                    |
+-----------------------------------------------------------------------------------+
        |                                |                               |
        v                                v                               v
+------------------+           +--------------------+          +--------------------+
|   ML INFERENCE   |           |  EXPLAINABLE AI    |          |  GENERATIVE AI     |
|   & PREDICTION   |           |  (SHAP ENGINE)     |          |  & RAG COPILOT     |
| - Pretrained     |           | - TreeExplainer    |          | - Multi-tier LLM:  |
|   Random Forest  |           | - Local Shapley    |          |   Groq / Gemini /  |
| - Decision Tree  |           |   Attribution      |          |   Ollama / Expert  |
| - Logistic Reg   |           | - Waterfall Push   |          | - TF-IDF Vector    |
| - Heuristics     |           |   Values           |          |   Store Indexer    |
|   Rule Fallback  |           | - Global Feature   |          | - Document Parsers |
| - StandardScaler |           |   Importance       |          |   (PDF, DOCX, TXT) |
+------------------+           +--------------------+          +--------------------+
        |                                |                               |
        +--------------------------------+-------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                         DATA & PERSISTENCE LAYER                                  |
|  - SQLite3 DB: `predictions`, `metrics`, `model_info`, `manual_documents`,        |
|                `conversation_history`                                             |
|  - Vector Store: `vector_store.json` (Document chunk embeddings & metadata)       |
|  - Local Storage: `/uploads`, `/reports`, `/models` (Vercel `/tmp` compatible)     |
+-----------------------------------------------------------------------------------+
```

### 4.1 Technology Component Breakdown
- **Backend Framework:** Python 3.11+, Flask 3.0.x
- **Data Manipulation & Math:** NumPy 1.26+, Pandas 2.1+
- **Machine Learning Suite:** Scikit-Learn 1.2+, XGBoost 1.7+, LightGBM
- **Explainability:** SHAP 0.43+ (TreeExplainer with surrogate additivity safety)
- **Generative AI & LLMs:** Groq SDK (`groq`), Google GenAI SDK (`google-genai`), Local Ollama REST client
- **Vector Search:** Lightweight In-Memory Cosine Similarity Vector Store with TF-IDF Vectorizer
- **Document Ingestion:** `pypdf`, `docx2txt`, `python-dotenv`
- **PDF Report Generation:** ReportLab 5.0+ with Flowable Platypus layouts
- **Frontend Core:** Semantic HTML5, Vanilla JavaScript (ES6+ Modules), Tailwind CSS
- **Visual Analytics:** ApexCharts 3.45+, Lucide Icon system

---

## 5. Data Specifications & Feature Engineering

### 5.1 The CIC-IDS2017 Benchmark
ThreatLens standardizes on the **CICIDS2017** network traffic flow dataset generated by the Canadian Institute for Cybersecurity. Raw network flow captures are preprocessed into bidirectional statistical records containing 79 standardized attributes.

### 5.2 The 12 Core Engineered Features
To achieve sub-millisecond inference latencies suitable for line-rate SOC telemetry, ThreatLens extracts a curated, highly discriminative 12-feature subset for model inference:

| Feature Name | Type | Description | Threat Relevance |
| :--- | :--- | :--- | :--- |
| **`Destination Port`** | Integer (0–65535) | The target service port (e.g., 80, 443, 22, 3306). | Isolates targeted service (SSH Brute Force vs. Web Flood). |
| **`Flow Duration`** | Float (µs) | Total duration of the bidirectional network flow in microseconds. | Short micro-bursts (PortScan) vs. persistent connections (DDoS). |
| **`Total Fwd Packets`** | Integer | Count of packets transmitted in the forward direction. | High volume indicates flooding or bulk exfiltration. |
| **`Total Length of Fwd Packets`** | Float (Bytes) | Aggregate payload byte size transmitted in forward packets. | Identifies heavy volumetric ingress attacks. |
| **`Fwd Packet Length Max`** | Float (Bytes) | Maximum packet size observed in the forward direction. | Detects jumbo frame exploitation or zero-byte probe packets. |
| **`Fwd Packet Length Mean`** | Float (Bytes) | Average size of forward packets. | Distinguishes text commands from large payload injections. |
| **`Bwd Packet Length Max`** | Float (Bytes) | Maximum packet size received in the reverse direction. | Identifies large server responses or amplification reflection. |
| **`Bwd Packet Length Mean`** | Float (Bytes) | Average size of reverse response packets. | Evaluates symmetric vs. asymmetric traffic patterns. |
| **`Flow Bytes/s`** | Float | Rate of throughput in bytes per second. | Volumetric saturation metric. |
| **`Flow Packets/s`** | Float | Rate of packet transmission per second. | High values (>500 pkt/s) strongly signal DDoS or port scans. |
| **`SYN Flag Count`** | Integer (0/1) | Indicates whether the TCP SYN synchronization flag is active. | Identifies SYN flood DDoS and half-open port scans. |
| **`ACK Flag Count`** | Integer (0/1) | Indicates whether the TCP ACK acknowledgment flag is active. | Validates completed handshakes vs. unsolicited probes. |

### 5.3 Payload Mapping & Fault Tolerance
The `map_payload_to_features()` function in `feature_engineering.py` automatically normalizes column names, removes leading/trailing whitespace, handles case-insensitivity, and substitutes zero for missing numeric values.

---

## 6. Machine Learning & Threat Classification Engine

### 6.1 Supported Threat Classes
ThreatLens detects four primary categories of network traffic:

```
                 +-----------------------+
                 |  Network Traffic Flow |
                 +-----------------------+
                             |
             +---------------+---------------+
             |                               |
             v                               v
    +-----------------+             +-----------------+
    |     BENIGN      |             |     ATTACK      |
    | (Normal Traffic)|             |  (Malicious)    |
    +-----------------+             +-----------------+
                                             |
                   +-------------------------+-------------------------+
                   |                         |                         |
                   v                         v                         v
          +-----------------+       +-----------------+       +-----------------+
          |      DDoS       |       |    PortScan     |       |   SSH-Patator   |
          | (High Rate/Vol) |       | (Reconnaissance)|       |  (Brute Force)  |
          +-----------------+       +-----------------+       +-----------------+
```

1. **`BENIGN` (Normal Traffic):** Standard web, DNS, database, and administrative traffic adhering to RFC transport standards.
2. **`DDoS` (Distributed Denial of Service):** Volumetric and protocol-based floods (HTTP flood, SYN flood, UDP amplification) saturating ingress buffers.
3. **`PortScan` (Reconnaissance):** Systematic probing of network ports to map active services, characterized by rapid packet rates, single forward packets, and non-responsive targets.
4. **`SSH-Patator` (Brute-Force Authentication):** Repeated password guessing attacks directed against Port 22, marked by high connection frequency and balanced bidirectional packet exchange.

### 6.2 Preprocessing & Feature Scaling
- **StandardScaler (`scaler.pkl`):** Standardizes features by removing the mean and scaling to unit variance:
  $$z = \frac{x - \mu}{\sigma}$$
- **LabelEncoder (`label_encoder.pkl`):** Maps categorical threat labels to discrete integers (0: BENIGN, 1: DDoS, 2: PortScan, 3: SSH-Patator).

### 6.3 Multi-Model Comparison & Evaluation
ThreatLens includes a rigorous model evaluation framework (`evaluate_models.py`, `train_model.py`, `train_models.py`) comparing five algorithms:
- **Random Forest Classifier (Primary Production Baseline):** 100 estimators, max depth 12. Delivers optimal resistance to overfitting and native compatibility with Tree SHAP.
- **Decision Tree Classifier:** Max depth 10. Low-latency reference tree for explainability benchmarks.
- **Logistic Regression:** L-BFGS solver, multi-class One-vs-Rest formulation for linear baseline comparisons.
- **XGBoost Classifier:** Gradient-boosted decision trees for edge-case anomaly detection.
- **LightGBM Classifier:** Fast histogram-based tree optimization.

### 6.4 Serverless Heuristic Failover Classifier
In serverless or low-memory environments (such as Vercel Edge functions where compiled C-extensions may be constrained), ThreatLens activates `predict_flow_heuristic()`:
- **DDoS Heuristic:** Packet Rate > 1,000 pkt/s OR (Port in [80, 443] AND Rate > 500 pkt/s) $\rightarrow$ Critical Alert.
- **PortScan Heuristic:** Packet Rate > 80 pkt/s AND Port not in standard services $\rightarrow$ High Alert.
- **SSH Brute-Force Heuristic:** Destination Port == 22 AND Rate > 20 pkt/s $\rightarrow$ High Alert.
- **Normal Fallback:** Flows not exceeding thresholds $\rightarrow$ Low Risk Benign.

---

## 7. Explainable AI (XAI) & SHAP Framework

### 7.1 Game-Theoretic Foundation
ThreatLens implements **Shapley Additive exPlanations (SHAP)** rooted in cooperative game theory. For any given network connection flow $x$, the prediction $f(x)$ is decomposed as:
$$f(x) = \phi_0 + \sum_{i=1}^{M} \phi_i$$
Where $\phi_0$ is the base expected model output, and $\phi_i$ is the exact Shapley attribution weight of feature $i$.

### 7.2 Explainability Visualizations
1. **Interactive Force Plot:** Visualizes the dynamic tug-of-war between features pushing the score toward **Normal** (green force bars) and those pushing toward **Attack** (red force bars).
2. **Waterfall Decision Progression:** Traces step-by-step how each parameter sequentially shifts the probability from the base threshold (0.34) to the final confidence value.
3. **Global Feature Importance:** Ranks top network parameters across all historical SOC detections, highlighting `Destination Port`, `Flow Packets/s`, and `Flow Duration` as dominant indicators.
4. **Surrogate Calculation Fallback:** If tree additivity checks encounter floating-point tolerances on extreme outliers, ThreatLens computes surrogate normalized contributions to guarantee zero UI rendering failures.

---

## 8. Generative AI & RAG Security Copilot

### 8.1 Multi-Tier Model Cascade
To guarantee 100% uptime for incident response, the AI Copilot queries providers in an automated fallback sequence:

```
[User Query] 
     |
     v
[Tier 1: Groq API] (LLaMA 3.3 70B Versatile, Sub-second response)
     | (if key missing or rate-limited)
     v
[Tier 2: Google Gemini API] (Gemini 2.5 Flash, Deep Reasoning)
     | (if key missing or unavailable)
     v
[Tier 3: Local Ollama] (Local `llama3` / `mistral` container)
     | (if daemon offline)
     v
[Tier 4: Embedded Expert System] (Deterministic Rule-Based Engine with MITRE ATT&CK Playbooks)
```

### 8.2 RAG Knowledge Retrieval Pipeline
1. **Document Ingestion:** Users upload PDF guidelines, TXT playbooks, or Word manuals (`/api/documents/upload`).
2. **Recursive Text Chunking:** Documents are split into 500-character overlapping chunks (100-character overlap).
3. **Vector Embeddings:** Lightweight TF-IDF cosine similarity indexing stored in `vector_store.json`.
4. **Context Injection:** When an analyst asks about a flagged incident, the top 3 relevant manual sections are retrieved and injected directly into the LLM system prompt.

### 8.3 Contextual Modes
- **Professional Mode:** Balanced executive prose with actionable recommendations.
- **Concise Mode:** Rapid bulleted triage points for time-sensitive active incidents.
- **Technical Mode:** Deep packet dissection, exact MITRE ATT&CK mapping, and shell commands.

---

## 9. Functional Requirements

### FR-1: Real-Time SOC Command Center (Dashboard Overview)
- **FR-1.1:** Display six top-tier KPI metric cards: Total Packets Monitored, Normal Traffic, Malicious Traffic, ML Accuracy %, False Positive Rate %, and System Threat Level.
- **FR-1.2:** Dynamic ApexCharts live traffic line chart updating across TCP, UDP, and ICMP protocols.
- **FR-1.3:** Threat density heatmap illustrating attack frequency grouped by hour and day of week.
- **FR-1.4:** Protocol distribution donut chart breaking down flow compositions.
- **FR-1.5:** Real-time recent alerts feed linking directly to the incident slide-over drawer.
- **FR-1.6:** Live system operational log console displaying daemon timestamps.

### FR-2: Dataset Ingestion & Validation
- **FR-2.1:** Drag-and-drop CSV upload zone with file type validation (`.csv` only).
- **FR-2.2:** Maximum upload size limit of 32 MB enforced via Werkzeug.
- **FR-2.3:** Client-side visual progress bar indicating ingestion and feature weight calculation.
- **FR-2.4:** Dataset inspection statistics display: Total Rows, Columns, File Size, and File Name.
- **FR-2.5:** "Load Sample Dataset" one-click button loading pre-seeded enterprise CICIDS2017 baseline data.

### FR-3: Multi-Class Detection Pipeline
- **FR-3.1:** Single flow real-time REST prediction (`POST /api/predict`).
- **FR-3.2:** Batch array flow processing (`POST /api/predict/batch`).
- **FR-3.3:** Direct CSV file detection (`POST /api/predict/file`) parsing rows and classifying sequentially.
- **FR-3.4:** Real-Time Monitor inspection table displaying Flow ID, Source IP, Destination IP, Protocol, Prediction Badge, Confidence Score, Risk Level, and Action Drawer Trigger.
- **FR-3.5:** Search and filter controls supporting free-text IP/Port search and prediction type dropdowns (All, Normal, Attack, Suspicious).

### FR-4: Explainable AI & SHAP Insights
- **FR-4.1:** Local SHAP force plot rendering normalized Normal Push vs. Attack Push bars.
- **FR-4.2:** Waterfall progression list rendering exact numerical contributions per parameter.
- **FR-4.3:** Natural-language AI decision explanation card summarizing key contributing features.
- **FR-4.4:** Global feature importance horizontal bar chart dynamically populated from historical data.

### FR-5: Threat Intelligence Correlation
- **FR-5.1:** External threat intelligence query endpoint (`GET /api/threat?ip=x.x.x.x&port=xx`).
- **FR-5.2:** Modular integrations for VirusTotal, AbuseIPDB, Shodan, and AlienVault OTX.
- **FR-5.3:** Fallback mock threat intelligence generation providing ASN, ISP, Country, Reputation Score, and Known Abuse Vectors when API keys are unconfigured.

### FR-6: AI Security Copilot & Document Knowledge
- **FR-6.1:** Multi-turn interactive chat interface with session persistence (`/api/chat`).
- **FR-6.2:** Flow context binding (`flow_id` association) injecting active incident parameters into chat context.
- **FR-6.3:** Incident playbook semantic search (`GET /api/manual?q=query` and `GET /api/manual/global`).
- **FR-6.4:** Ingested manuals catalog showing document name, chunk count, file size, and upload date.
- **FR-6.5:** Conversation history clearing and session reset capabilities.

### FR-7: Incident Mitigation & Remediation Procedures
- **FR-7.1:** Slide-over Attack Details Drawer rendering complete packet telemetry, SHAP breakdown, and recommended remediation.
- **FR-7.2:** "Apply Port Mitigation Block" interactive trigger executing simulated edge firewall isolation rules (`iptables -A INPUT -s <IP> -j DROP`).
- **FR-7.3:** "Consult AI Copilot" shortcut transferring the incident context directly to the conversational agent.

### FR-8: Audit & Forensic Report Generation
- **FR-8.1:** Export full threat audit logs in **PDF** format formatted with corporate headers, summary KPI tables, and critical incident breakdowns.
- **FR-8.2:** Export audit logs in **CSV** format for SIEM/Splunk ingestion.
- **FR-8.3:** Export audit logs in structured **JSON** format for REST automation.
- **FR-8.4:** One-click **AI Copilot Incident Brief PDF** (`GET /api/reports/ai?flow_id=...`) providing forensic executive analysis for an isolated attack.

### FR-9: SOC Settings & Classification Calibration
- **FR-9.1:** Classification Alert Threshold slider allowing adjustment from 0.05 to 0.95 (default 0.50).
- **FR-9.2:** Audio alert toggle for browser-based chime notifications on high-risk intrusions.
- **FR-9.3:** Secure API key management panel saving Groq and Gemini credentials to local environment.

### FR-10: Authentication & Session Access
- **FR-10.1:** Hardcoded administrative credentials (`admin` / `password123`) supporting both JSON API and HTML form authentication.
- **FR-10.2:** JWT-compatible secret configuration (`JWT_SECRET_KEY`, 1-hour expiration).
- **FR-10.3:** Session logout clearing active user tokens and redirecting to login portal.

---

## 10. Non-Functional Requirements

### NFR-1: Performance & Latency
- **Inference Latency:** Single network flow prediction must execute in $\le 50\text{ ms}$ (P95) under standard CPU operation.
- **Batch Processing:** File detection pipeline must process at least $100\text{ records/second}$.
- **Dashboard Load Time:** Primary dashboard shell must achieve First Contentful Paint (FCP) $\le 1.2\text{ s}$ over broadband.

### NFR-2: Scalability & Serverless Compatibility
- **Stateless Design:** Application endpoints must operate cleanly on stateless serverless runtimes (e.g., Vercel, AWS Lambda) using `/tmp` directory redirection for databases and uploads.
- **Thread Safety:** Database connection helper (`get_db_connection`) must open and close isolated SQLite connections per thread to prevent cross-thread lock exceptions.

### NFR-3: Reliability & Graceful Degradation
- **Multi-Level Fallback:** If machine learning dependencies or serialized model weights fail to load, the system must transparently fall back to the rule-based heuristic classifier without returning 500 errors.
- **LLM Resilience:** If remote GenAI API keys are invalid or quotas are exceeded, the Embedded Expert System must immediately take over chat interactions.

### NFR-4: Security & Data Protection
- **Input Sanitization:** All incoming files must be sanitized using `secure_filename()` to prevent directory traversal attacks.
- **Payload Validation:** JSON inputs must be strictly validated against required network flow keys.
- **Credential Masking:** API keys returned via `/api/settings` must only return boolean status flags (`gemini_api_key_set`), never raw secret strings.

### NFR-5: Accessibility & UX Ergonomics
- **Dark Mode Ergonomics:** Designed to reduce eye strain during extended SOC night shifts using `#0B1120` canvas colors and curated cyan/purple accent glows.
- **Mobile Responsiveness:** Fully functional responsive design adapting down to 375px mobile screens with floating hamburger toggles and backdrop blurs.

### NFR-6: Maintainability & Code Hygiene
- **Zero Placeholder Code:** All functional modules, charts, and API endpoints must contain working production logic.
- **Extensive Test Coverage:** Unit test suite covering models, preprocessors, validators, services, and REST routes.

---

## 11. API Endpoint Interface Specifications

| HTTP Method | Endpoint | Description | Request Body / Query Params | Success Response | Status Codes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/` | Serves public landing page. | None | HTML | `200` |
| `GET` / `POST` | `/login` | Authenticates administrator session. | `{ "username": "...", "password": "..." }` | `{ "status": "success", "redirect": "/dashboard" }` | `200`, `401` |
| `GET` | `/dashboard` | Serves SOC Command Center UI. | None | HTML | `200` |
| `GET` | `/api/health` | Service health status check. | None | `{ "status": "success", "state": "UP", "version": "..." }` | `200` |
| `GET` | `/api/dashboard` | Compiles aggregate SOC packet metrics. | None | `{ "status": "success", "data": { ...metrics } }` | `200`, `500` |
| `GET` | `/api/recent-attacks` | Returns top 10 malicious threat alerts. | None | `{ "status": "success", "data": [ ...attacks ] }` | `200`, `500` |
| `GET` | `/api/model-info` | Returns active ML classifier metrics. | None | `{ "status": "success", "data": { ...model_info } }` | `200`, `404` |
| `POST` | `/api/upload` | Ingests CSV dataset file and validates schema. | `multipart/form-data` with `file` | `{ "status": "success", "data": { rows, cols, size, filepath } }` | `200`, `400`, `422` |
| `POST` | `/api/predict` | Predicts threat for single network flow. | `{ flow_id, src_ip, dst_ip, protocol, port, payload, threshold }` | `{ "status": "success", "data": { prediction, confidence, risk_level, explanation, shap_values } }` | `200`, `400`, `422`, `500` |
| `POST` | `/api/predict/batch` | Ingests array of flow packets for prediction. | `{ "flows": [ ...flows ], "threshold": 0.50 }` | `{ "status": "success", "processed": N, "errors": 0, "data": [...] }` | `200`, `400` |
| `POST` | `/api/predict/file` | Executes predictions on an uploaded CSV file. | `{ "filepath": "...", "threshold": 0.50 }` | `{ "status": "success", "processed": N, "message": "..." }` | `200`, `400`, `422` |
| `GET` | `/api/predict/history` | Fetches historical log predictions. | `q` (string), `filter` (string), `limit` (int) | `{ "status": "success", "data": [ ...records ] }` | `200` |
| `GET` | `/api/shap/<flow_id>` | Retrieves pre-computed SHAP explanation. | Path parameter `flow_id` | `{ "status": "success", "data": { ...shap_explanation } }` | `200`, `404` |
| `GET` | `/api/shap/importance` | Returns global feature importance weights. | None | `{ "status": "success", "data": { features: [...], values: [...] } }` | `200` |
| `GET` | `/api/threat` | Compiles IP/Port threat intelligence. | `ip` (required), `port` (optional) | `{ "status": "success", "data": { ip, risk_score, asn, abuse_history } }` | `200`, `400` |
| `POST` | `/api/chat` | Interacts with AI Security Copilot. | `{ session_id, message, flow_id, mode }` | `{ "status": "success", "data": { "response": "..." } }` | `200`, `400`, `500` |
| `GET` | `/api/chat/history` | Retrieves conversation history for session. | `session_id` | `{ "status": "success", "data": [ ...messages ] }` | `200` |
| `POST` | `/api/chat/clear` | Wipes active session conversation memory. | `{ "session_id": "..." }` | `{ "status": "success", "message": "..." }` | `200` |
| `POST` | `/api/documents/upload`| Uploads manual (PDF/TXT/DOCX) to RAG store. | `multipart/form-data` with `file` | `{ "status": "success", "data": { filename, chunks_indexed } }` | `200`, `400`, `422` |
| `GET` | `/api/documents/list` | Lists all indexed operational manuals. | None | `{ "status": "success", "data": [ ...manuals ] }` | `200` |
| `GET` | `/api/manual` | Semantic vector search on manuals. | `q` (search query) | `{ "status": "success", "data": [ ...matches ] }` | `200`, `400` |
| `GET` | `/api/reports/download`| Downloads compiled audit report. | `format` (`pdf`, `csv`, `json`) | File binary attachment | `200`, `400` |
| `GET` | `/api/reports/ai` | Downloads individual AI incident brief. | `flow_id` (required) | PDF binary attachment | `200`, `400`, `404` |
| `GET` | `/api/settings` | Returns API key configuration status. | None | `{ "status": "success", "data": { gemini_api_key_set, groq_api_key_set } }` | `200` |
| `POST` | `/api/settings` | Updates Groq / Gemini API credentials. | `{ gemini_api_key, groq_api_key }` | `{ "status": "success", "message": "..." }` | `200`, `500` |

---

## 12. Database Schema & Data Persistence

ThreatLens utilizes an embedded SQLite3 relational database (`database.db`) featuring structured tables:

### 12.1 Table: `predictions`
Stores all evaluated network flow predictions and their SHAP explanations.
```sql
CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT UNIQUE NOT NULL,
    timestamp DATETIME NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    prediction TEXT NOT NULL,      -- 'Normal', 'Attack', 'Suspicious'
    confidence REAL NOT NULL,        -- Percentage (e.g., 99.42)
    risk_level TEXT NOT NULL,        -- 'Low', 'Moderate', 'High', 'Critical'
    attack_type TEXT NOT NULL,       -- 'DDoS', 'PortScan', 'SSH-Patator', 'None'
    explanation TEXT NOT NULL,       -- Natural language explanation
    shap_values TEXT NOT NULL        -- JSON string of feature weight contributions
);
CREATE INDEX IF NOT EXISTS idx_pred_flow_id ON predictions(flow_id);
CREATE INDEX IF NOT EXISTS idx_pred_timestamp ON predictions(timestamp);
```

### 12.2 Table: `metrics`
Stores temporal snapshots of system-wide traffic throughput and intrusion ratios.
```sql
CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    total_packets INTEGER NOT NULL,
    total_attacks INTEGER NOT NULL,
    normal_packets INTEGER NOT NULL,
    malicious_packets INTEGER NOT NULL,
    accuracy REAL NOT NULL,
    fpr REAL NOT NULL,
    threat_level TEXT NOT NULL       -- 'LOW', 'MODERATE', 'HIGH', 'CRITICAL'
);
```

### 12.3 Table: `model_info`
Tracks registered machine learning models and comparative evaluation metrics.
```sql
CREATE TABLE IF NOT EXISTS model_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name TEXT NOT NULL,
    accuracy REAL NOT NULL,
    precision REAL NOT NULL,
    recall REAL NOT NULL,
    f1_score REAL NOT NULL,
    roc_auc REAL NOT NULL,
    trained_at DATETIME NOT NULL,
    active INTEGER DEFAULT 0         -- 1 for currently active model, 0 otherwise
);
```

### 12.4 Table: `manual_documents`
Catalogs ingested incident response playbooks and reference manuals.
```sql
CREATE TABLE IF NOT EXISTS manual_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    upload_date DATETIME NOT NULL,
    file_size INTEGER NOT NULL,
    chunks_count INTEGER NOT NULL,
    status TEXT DEFAULT 'indexed'
);
```

### 12.5 Vector Store Schema (`vector_store.json`)
The RAG subsystem persists document chunks as structured JSON objects:
```json
{
  "documents": [
    {
      "id": "doc-uuid-001",
      "text": "Section 4.2: To mitigate a SYN flood on Port 80, apply rate-limiting in iptables...",
      "metadata": {
        "source": "firewall_hardening_guide.pdf",
        "chunk_index": 4,
        "total_chunks": 28
      }
    }
  ]
}
```

---

## 13. Incident Response & Remediation Procedures

### 13.1 Playbook Matrix

| Attack Category | Threat Vector | Automated Remediation Action | Manual Analyst Procedure |
| :--- | :--- | :--- | :--- |
| **DDoS Ingress Exploit** | High packet rate flood on Port 80/443 | `iptables -I INPUT -s <SRC_IP> -j DROP` | Enable Cloudflare/Edge WAF under-attack mode; review upstream ISP flow telemetry. |
| **Port Scanner Recon** | Rapid sweep across ports 1–65535 | `iptables -A INPUT -p tcp -s <SRC_IP> --syn -j DROP` | Block IP range at boundary gateway; inspect internal honeypot logs for lateral movement. |
| **SSH Brute-Force Auth** | Repeated failed logins on Port 22 | `fail2ban-client set sshd banip <SRC_IP>` | Disable password-based SSH authentication; enforce Ed25519 public key auth and 2FA. |
| **Anomalous Outlier** | Unbalanced Down/Up ratios or abnormal flags | Quarantine connection interface | Trigger full pcap capture for deep packet inspection in Wireshark. |

---

## 14. Security, Governance & Compliance

1. **Least Privilege Principle:** Access to the SOC command center is gated behind authenticated sessions.
2. **Stateless Secret Handling:** API keys for external intelligence and LLM services are loaded dynamically from environment variables or saved with 600 filesystem permissions.
3. **Data Protection:** Network payloads processed in memory are stripped of proprietary organizational secrets before being stored in SQLite.
4. **Audit Trail Integrity:** Incident reports include generation timestamps, analyst IDs, and tamper-resistant checksum hashes suitable for SOC2 Type II and ISO 27001 audit reviews.

---

## 15. Testing, Verification & Quality Assurance

ThreatLens mandates rigorous verification across three testing tiers:
1. **Unit Testing (`tests/test_backend.py`):**
   - Validation testing: `allowed_file`, `validate_flow_payload`, `validate_csv_dataset`.
   - Database operations: table schemas, migrations, metric updates.
   - Core inference: prediction pipeline, SHAP tree explainers, surrogate calculation fallbacks.
   - REST API endpoints: health, login, dashboard metrics, reports, chat sessions.
2. **Automated Dataset Validation (`test_with_dataset.py`):**
   - High-volume ingestion test of $\ge 1,000$ synthetic network flow records.
   - Automated evaluation of throughput, detection distribution, confidence intervals, and database write integrity.
3. **End-to-End Browser & UX Testing:**
   - Visual verification of glassmorphism styling, ApexCharts rendering, drag-and-drop file ingestion, and slide-over drawers.

---

## 16. Release Roadmap & Future Milestones

```
+-----------------------------------------------------------------------------------------+
|                                  THREATLENS ROADMAP                                     |
+-----------------------------------------------------------------------------------------+
| Milestone 1: v1.0.4 (Current Baseline)                                                  |
| - Production Random Forest classifier with 12 core CICIDS2017 features                  |
| - SHAP Local Force and Global Importance explainability engine                          |
| - Multi-tier RAG Security Copilot (Groq, Gemini, Ollama, Embedded Expert)               |
| - Drag-and-drop CSV dataset ingestion & PDF/CSV/JSON report generator                   |
+-----------------------------------------------------------------------------------------+
                                            |
                                            v
+-----------------------------------------------------------------------------------------+
| Milestone 2: v1.1.0 (Q1 2027)                                                           |
| - Apache Kafka / RabbitMQ streaming ingestion for live 10Gbps enterprise taps           |
| - Live eBPF Linux kernel packet capture probe integration                               |
| - Bi-directional STIX / TAXII automated threat intelligence feed exchange              |
+-----------------------------------------------------------------------------------------+
                                            |
                                            v
+-----------------------------------------------------------------------------------------+
| Milestone 3: v1.2.0 (Q2 2027)                                                           |
| - Multi-tenant Role-Based Access Control (RBAC) with SAML / Okta SSO                   |
| - Fine-tuned Cyber-LLaMA local model containerized for on-premise air-gapped deployments|
| - Kubernetes Helm chart deployment manifests with horizontal pod autoscaling            |
+-----------------------------------------------------------------------------------------+
```

---

*ThreatLens Architecture Document — Confidential — For SOC Engineering & Governance*
