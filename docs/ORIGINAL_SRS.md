# Software Requirements Specification (SRS)

## Project Title

**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**

### Alternative Academic Title

**AI-Driven Cyber Threat Detection Using Unidirectional IP Traffic Analysis**

---

# 1. Introduction

## 1.1 Purpose

The purpose of this project is to design and develop an Artificial Intelligence based cybersecurity system capable of detecting malicious network activities by analyzing **unidirectional IP traffic**.

Traditional network intrusion detection systems may depend on bidirectional communication information. However, in some networks only one direction of communication may be visible to the monitoring system.

The proposed system analyzes available one-way traffic characteristics and uses Machine Learning algorithms to determine whether a network flow is normal or potentially malicious.

The system will provide:

- Network traffic analysis
- Unidirectional flow processing
- AI-based threat detection
- Attack classification
- Threat probability
- Risk-level calculation
- Security alerts
- Dashboard visualization
- Historical threat records
- Machine Learning performance analysis

---

# 2. Problem Statement

Modern computer networks generate enormous amounts of traffic every second.

Cyber attackers may perform activities such as:

- Denial-of-Service attacks
- Distributed Denial-of-Service attacks
- Reconnaissance
- Port scanning
- Exploitation
- Botnet communication
- Brute-force attempts
- Abnormal connection activity

Traditional detection mechanisms frequently depend on predefined signatures or complete communication information.

However, in real-world monitoring environments, security systems may only observe traffic moving in one direction.

Example:

```text
Host A --------------------> Server B

Available for analysis:
A → B

Reverse traffic:
A ← B

May not be available

```

Therefore, there is a need for an intelligent system capable of detecting cyber threats using only the available **unidirectional traffic information**.

---

# 3. Objectives

The major objectives of the proposed system are:

1. Collect or load network traffic data.
2. Analyze unidirectional IP traffic.
3. Extract useful network-flow features.
4. Clean and preprocess network datasets.
5. Identify important features associated with malicious activity.
6. Train multiple Machine Learning models.
7. Compare ML models using cybersecurity-specific performance metrics.
8. Detect normal and malicious network traffic.
9. Classify different categories of cyber attacks.
10. Generate a probability score for detected threats.
11. Assign risk levels to network activity.
12. Display security information through a dashboard.
13. Store detected threats for future investigation.
14. Reduce false-negative and false-positive predictions.
15. Compare unidirectional and bidirectional traffic detection performance.
16. Provide a foundation for future real-time network monitoring.

---

# 4. Scope of the Project

The project focuses primarily on AI-based analysis of structured network-flow information.

The system will initially work with publicly available cybersecurity datasets.

The project may later be extended to process traffic collected using:

- Wireshark
- Zeek
- NetFlow/IPFIX
- Other traffic monitoring tools

The system is designed as a **defensive cybersecurity research and monitoring platform**.

---

# 5. Project Scope Includes

The system will support:

- Dataset upload
- Dataset preprocessing
- Network-flow analysis
- Unidirectional flow feature generation
- Feature selection
- Machine Learning training
- Machine Learning testing
- Threat prediction
- Threat classification
- Probability calculation
- Risk scoring
- Security dashboard
- Threat logging
- Visualization
- Performance evaluation
- Model comparison

---

# 6. Project Scope Does Not Include

The first version will not:

- Automatically attack external systems
- Perform penetration testing against unauthorized networks
- Automatically block Internet traffic
- Replace enterprise IDS/IPS products
- Guarantee detection of every zero-day attack
- Inspect encrypted payload contents
- Track individual users
- Perform offensive cybersecurity operations

The project is intended for legitimate defensive, educational, and research purposes.

---

# 7. Proposed System

The proposed system uses Artificial Intelligence and Machine Learning to analyze characteristics of unidirectional network flows.

Basic architecture:

```text
Network Traffic / Dataset
            |
            v
+----------------------------+
| Traffic Collection Module  |
+----------------------------+
            |
            v
+----------------------------+
| Unidirectional Flow Engine |
+----------------------------+
            |
            v
+----------------------------+
| Feature Extraction         |
+----------------------------+
            |
            v
+----------------------------+
| Data Preprocessing         |
+----------------------------+
            |
            v
+----------------------------+
| Feature Selection          |
+----------------------------+
            |
            v
+----------------------------+
| Machine Learning Model     |
+----------------------------+
            |
            v
+----------------------------+
| Threat Detection Engine    |
+----------------------------+
            |
            v
+----------------------------+
| Risk Scoring Engine        |
+----------------------------+
            |
            v
+----------------------------+
| Dashboard / Alert System   |
+----------------------------+
            |
            v
+----------------------------+
| Database / Threat History  |
+----------------------------+

```

---

# 8. Target Users

## 8.1 Administrator

Administrator manages:

- Users
- Dataset configuration
- ML models
- Application settings
- System logs

## 8.2 Security Analyst

Security analyst can:

- Monitor network activity
- View detected threats
- Check threat scores
- Inspect attack information
- View historical alerts
- Analyze model predictions

## 8.3 Researcher

Researcher can:

- Upload datasets
- Train models
- Compare algorithms
- Evaluate feature importance
- Generate performance reports

## 8.4 Student

Student can use the system to learn:

- Network security
- Artificial Intelligence
- Machine Learning
- Network traffic analysis
- Intrusion detection

---

# 9. Functional Requirements

## FR-01: User Authentication

The system should provide authentication for authorized users.

Users should be able to:

- Login
- Logout
- Access permitted modules

Optional roles:

```text
Administrator
Security Analyst
Researcher

```

---

# 10. FR-02: Dataset Upload

The system shall allow authorized users to upload supported network datasets.

Supported formats may include:

```text
CSV
JSON
PCAP – advanced version
Zeek logs – advanced version

```

For the first version, CSV will be the primary input.

---

# 11. FR-03: Dataset Validation

The system shall validate uploaded data.

Validation shall include:

- File type
- Missing columns
- Empty dataset
- Invalid numerical values
- Duplicate records
- Missing labels
- Unsupported features

---

# 12. FR-04: Data Preprocessing

The system shall preprocess the network dataset.

Processes may include:

```text
Missing-value handling
Infinite-value removal
Duplicate removal
Categorical encoding
Feature scaling
Outlier analysis
Data normalization
Class-balancing analysis

```

---

# 13. FR-05: Unidirectional Traffic Processing

The application shall create or retain network features representing traffic in one direction.

Example:

```text
Source → Destination

```

The system should avoid depending on reverse-flow information for the primary unidirectional experiment.

---

# 14. FR-06: Feature Extraction

The system should extract or utilize features such as:

- Source port
- Destination port
- Protocol
- Flow duration
- Packet count
- Byte count
- Packets per second
- Bytes per second
- Minimum packet length
- Maximum packet length
- Average packet length
- Packet-length variance
- SYN flag count
- ACK flag count
- FIN flag count
- RST flag count
- Inter-arrival time
- Connection frequency
- Unique destination count
- Unique destination port count
- Flow start time
- Flow end time

Exact features will depend on the selected dataset.

---

# 15. FR-07: Feature Selection

The system shall support selecting useful attributes for Machine Learning.

Feature selection may use:

- Correlation analysis
- Feature importance
- Recursive Feature Elimination
- Mutual information
- Statistical analysis

The system should avoid obvious data-leakage features.

---

# 16. FR-08: Dataset Splitting

The application shall divide data into appropriate subsets.

Example:

```text
Training Data   : 70%
Validation Data : 15%
Testing Data    : 15%

```

or

```text
Training : 80%
Testing  : 20%

```

The exact configuration may be configurable.

Where appropriate, the project should also investigate time-aware or source-aware splits to reduce unrealistic leakage.

---

# 17. FR-09: Machine Learning Training

The system shall support training multiple Machine Learning algorithms.

Initial algorithms:

```text
Logistic Regression
Decision Tree
Random Forest
XGBoost

```

Optional advanced algorithms:

```text
Support Vector Machine
Artificial Neural Network
Autoencoder
LSTM
1D CNN
Transformer-based model

```

---

# 18. FR-10: Model Comparison

The system shall compare trained models.

Comparison shall include:

- Accuracy
- Precision
- Recall
- F1-score
- ROC-AUC where appropriate
- PR-AUC where appropriate
- False Positive Rate
- False Negative Rate
- Training time
- Prediction time

---

# 19. FR-11: Best Model Selection

The system shall allow selecting the best-performing model.

The best model should not be selected using accuracy alone.

Preference should be given to models with a good balance of:

```text
Recall
F1-score
False Negative Rate
False Positive Rate
Inference Speed

```

---

# 20. FR-12: Binary Threat Detection

The initial AI model shall be capable of predicting:

```text
NORMAL
or
ATTACK

```

Example:

```text
Input Flow
      ↓
AI Model
      ↓
ATTACK
Probability = 95%

```

---

# 21. FR-13: Multi-Class Attack Detection

The advanced system shall support attack-category prediction where dataset labels permit.

Possible classes include:

```text
Normal
DoS
DDoS
Reconnaissance
Exploits
Bot Activity
Scanning
Brute Force
Other Attack

```

Actual categories will depend on the selected dataset.

---

# 22. FR-14: Threat Probability

The application shall produce a confidence/probability score when supported by the selected model.

Example:

```text
Threat Probability

94%

```

---

# 23. FR-15: Risk Scoring

The application shall convert predictions into understandable security-risk levels.

Example:

```text
0 – 25%    LOW
26 – 50%   MEDIUM
51 – 75%   HIGH
76 – 100%  CRITICAL

```

The final thresholds should be configurable and calibrated using evaluation data rather than treated as universal security standards.

---

# 24. FR-16: Security Alerts

When suspicious activity is detected, the system shall create an alert containing:

```text
Alert ID
Timestamp
Source information
Destination information
Protocol
Predicted attack
Threat probability
Risk level
Model used

```

---

# 25. FR-17: Dashboard

The system shall provide a graphical dashboard.

The dashboard should display:

- Total flows analyzed
- Normal flows
- Suspicious flows
- Attack count
- Attack distribution
- Risk-level distribution
- Recent alerts
- Model performance
- Threat history

Example:

```text
=================================================
     AI CYBER THREAT DETECTION PLATFORM
=================================================

Total Flows              25,482
Normal                   24,150
Threats Detected          1,332

HIGH RISK                    82
CRITICAL                     19

-------------------------------------------------

Latest Detection

Protocol                   TCP
Destination Port           443

Predicted Threat:
DDoS

Threat Probability:
94%

Risk Level:
CRITICAL

```

---

# 26. FR-18: Threat History

The application shall store detected alerts.

The user should be able to filter historical data using:

```text
Date
Attack type
Risk level
Protocol
Source
Destination

```

---

# 27. FR-19: Visualization

The application shall display visualizations such as:

- Attack distribution
- Normal vs malicious traffic
- Model comparison
- Confusion matrix
- Feature importance
- Threat trends
- Risk-level distribution

---

# 28. FR-20: Model Performance Report

The application should generate performance results for each model.

Example:

| ModelAccuracyPrecisionRecallF1 |        |        |        |        |
| ------------------------------ | ------ | ------ | ------ | ------ |
| Logistic Regression            | Result | Result | Result | Result |
| Decision Tree                  | Result | Result | Result | Result |
| Random Forest                  | Result | Result | Result | Result |
| XGBoost                        | Result | Result | Result | Result |

Actual values shall be generated only after training and evaluation.

---

# 29. FR-21: Unidirectional vs Bidirectional Comparison

A major research component shall compare:

```text
Unidirectional Traffic
          VS
Bidirectional Traffic

```

The comparison may include:

| MetricUni-flowBi-flow |        |        |
| --------------------- | ------ | ------ |
| Accuracy              | Result | Result |
| Precision             | Result | Result |
| Recall                | Result | Result |
| F1                    | Result | Result |
| False Positive Rate   | Result | Result |
| False Negative Rate   | Result | Result |
| Prediction Time       | Result | Result |

This experiment answers the research question:

> How effectively can cyber threats be detected when only one direction of network traffic is available?

---

# 30. FR-22: Model Saving

The trained ML model shall be stored for later prediction.

Possible format:

```text
.joblib
.pkl
.json / model-specific format

```

The project should record the model version and feature schema together.

---

# 31. FR-23: Prediction Module

The system shall load the saved ML model and use it for predictions without retraining every time.

---

# 32. FR-24: Model Versioning

The system should maintain information about:

```text
Model name
Version
Training date
Dataset
Feature set
Performance
Hyperparameters

```

---

# 33. FR-25: Report Generation

The application should support generation of project/security reports containing:

- Number of analyzed flows
- Threat count
- Attack types
- Risk statistics
- Model results
- Performance metrics
- Important features
- Detection summary

---

# 34. Non-Functional Requirements

## NFR-01: Performance

The system should process dataset records efficiently.

For the final demonstration, predictions should be produced quickly enough for interactive use.

---

# 35. NFR-02: Accuracy

The AI model should provide reliable predictions on unseen test data.

Evaluation should focus on:

```text
Precision
Recall
F1-score
False Positive Rate
False Negative Rate

```

No fixed accuracy shall be claimed before experimentation.

---

# 36. NFR-03: Scalability

The architecture should allow future processing of larger datasets and continuous traffic streams.

---

# 37. NFR-04: Reliability

The system should:

- Detect invalid inputs
- Handle processing errors
- Log errors
- Prevent application crashes where possible

---

# 38. NFR-05: Usability

The interface should:

- Be simple
- Have readable labels
- Display understandable threat information
- Avoid requiring advanced ML knowledge for basic use

---

# 39. NFR-06: Maintainability

The application should have modular source code.

Recommended separation:

```text
Data Collection
Preprocessing
Feature Engineering
Machine Learning
Prediction
Database
Dashboard
Reports

```

---

# 40. NFR-07: Portability

The project should run primarily on:

```text
Windows 10/11
Linux – optional

```

Docker may later improve portability.

---

# 41. NFR-08: Security

Security requirements include:

- Input validation
- Safe file-upload handling
- Authentication
- Password hashing if accounts are implemented
- Restricted administrative access
- Database protection
- Secure session handling
- Application logging

---

# 42. NFR-09: Privacy

The system should avoid unnecessary packet-payload inspection.

Flow metadata should be preferred where possible.

Example:

```text
Packet count
Byte count
Ports
Protocol
Timing
TCP flags

```

Sensitive payload content should not be collected unless explicitly necessary and legally authorized.

---

# 43. Dataset Requirements

The initial recommended dataset is:

## UNSW-NB15

The project may later compare performance with datasets such as:

```text
CICIDS2017
TON_IoT
Other legitimate cybersecurity datasets

```

Dataset requirements:

- Normal traffic records
- Malicious traffic records
- Suitable labels
- Network-flow attributes
- Enough samples for training/testing

---

# 44. Data Preprocessing Requirements

The preprocessing module shall perform appropriate operations including:

```text
Load Dataset
      ↓
Inspect Columns
      ↓
Remove Duplicates
      ↓
Handle Missing Values
      ↓
Handle Infinite Values
      ↓
Encode Categorical Fields
      ↓
Select Features
      ↓
Analyze Class Distribution
      ↓
Split Dataset

```

---

# 45. Machine Learning Requirements

## Input

Structured network-flow features.

## Output

```text
Prediction
Attack Type
Probability
Risk Level

```

## Minimum Models

- Logistic Regression
- Decision Tree
- Random Forest
- XGBoost

---

# 46. Model Evaluation Requirements

The project should create:

```text
Classification Report
Confusion Matrix
Precision
Recall
F1-score
Accuracy
ROC-AUC where suitable
PR-AUC where suitable
False Positive Rate
False Negative Rate

```

---

# 47. User Interface Requirements

The dashboard should contain the following pages.

## Page 1 – Home Dashboard

Displays:

```text
Total flows
Threat count
Normal count
Critical threats
Recent alerts

```

## Page 2 – Dataset

Features:

```text
Upload dataset
Preview dataset
Dataset statistics
Class distribution

```

## Page 3 – Model Training

Features:

```text
Choose model
Train model
Display training status
Display result

```

## Page 4 – Model Comparison

Displays:

```text
Accuracy
Precision
Recall
F1-score
Confusion Matrix

```

## Page 5 – Threat Detection

Allows users to:

```text
Upload traffic features
or
Enter a flow
        ↓
Predict

```

Output:

```text
Prediction
Attack category
Probability
Risk level

```

## Page 6 – Threat History

Displays stored security alerts.

## Page 7 – Analytics

Displays:

- Attack distribution
- Threat trends
- Feature importance
- Model comparison

---

# 48. Database Requirements

The initial version may use:

**SQLite**

Advanced version:

**PostgreSQL**

Possible tables:

```text
users
datasets
models
network_flows
predictions
alerts
audit_logs

```

---

# 49. Example Database Design

## USERS

```text
user_id
name
email
password_hash
role
created_at

```

## MODELS

```text
model_id
model_name
version
dataset_name
accuracy
precision
recall
f1_score
created_at

```

## NETWORK\_FLOWS

```text
flow_id
timestamp
source_ip
destination_ip
source_port
destination_port
protocol
packet_count
byte_count
duration

```

For production deployments, IP-address retention should follow applicable privacy and security requirements.

## ALERTS

```text
alert_id
flow_id
prediction
attack_type
probability
risk_level
timestamp

```

---

# 50. API Requirements

If FastAPI is implemented, possible endpoints include:

```text
POST /login

POST /dataset/upload

POST /model/train

GET /models

POST /predict

GET /alerts

GET /alerts/{id}

GET /analytics

GET /model/performance

```

---

# 51. Software Requirements

## Core Software

```text
Python 3.x
VS Code
Jupyter Notebook
Git
GitHub

```

## Python Libraries

```text
Pandas
NumPy
Scikit-learn
XGBoost
Matplotlib
Joblib

```

## Dashboard

```text
Streamlit

```

## Database

```text
SQLite

```

## Network Tools

```text
Wireshark
Zeek – advanced version

```

## Advanced Backend

```text
FastAPI

```

## Deployment

```text
Docker

```

---

# 52. Hardware Requirements

## Minimum

```text
Processor : Intel Core i3 / equivalent
RAM       : 8 GB
Storage   : 20 GB available
Internet  : Dataset/software downloads

```

## Recommended

```text
Processor : Intel Core i5 / Ryzen 5 or above
RAM       : 16 GB
Storage   : 50 GB SSD available
OS        : Windows 10/11 or Linux

```

GPU:

```text
Not required for initial ML implementation.

```

---

# 53. External Interface Requirements

## User Interface

Browser-based Streamlit dashboard.

## Software Interface

The system may interact with:

```text
CSV Dataset
SQLite
Machine Learning models
Wireshark
Zeek
FastAPI

```

## Network Interface

Advanced versions may receive flow information from a network-monitoring interface.

---

# 54. Use Case 1 – Upload Dataset

### Actor

Researcher

### Steps

```text
1. User opens Dataset page.
2. User selects CSV dataset.
3. System validates the file.
4. System loads dataset.
5. System shows preview.
6. System displays dataset statistics.

```

### Result

Dataset is available for preprocessing.

---

# 55. Use Case 2 – Train Model

### Actor

Researcher

### Steps

```text
1. User selects algorithm.
2. System loads prepared dataset.
3. System divides training/testing data.
4. System trains model.
5. System evaluates model.
6. System stores model.
7. System displays performance.

```

---

# 56. Use Case 3 – Detect Threat

### Actor

Security Analyst

### Steps

```text
1. Network-flow data is provided.
2. System preprocesses input.
3. AI model analyzes traffic.
4. Prediction is generated.
5. Threat probability is calculated.
6. Risk level is generated.
7. Result is displayed.
8. Suspicious results are stored.

```

---

# 57. Use Case 4 – View Alerts

### Actor

Security Analyst

### Steps

```text
1. Analyst opens Alerts page.
2. System retrieves threat history.
3. Analyst filters alerts.
4. Analyst selects an alert.
5. System displays threat information.

```

---

# 58. Use Case 5 – Compare Models

### Actor

Researcher

### Steps

```text
1. Researcher trains multiple models.
2. System stores evaluation results.
3. Researcher opens comparison page.
4. System compares metrics.
5. Best model can be selected.

```

---

# 59. Use Case Diagram – Text Representation

```text
                    +---------------------+
                    |        USER         |
                    +----------+----------+
                               |
          +--------------------+--------------------+
          |                    |                    |
          v                    v                    v
    Upload Dataset       Train ML Model       Detect Threat
          |                    |                    |
          v                    v                    v
    Preprocess Data      Compare Models       Risk Scoring
          |                    |                    |
          +--------------------+--------------------+
                               |
                               v
                         View Dashboard
                               |
                               v
                         View Alerts
                               |
                               v
                       Generate Reports

```

---

# 60. Data Flow Diagram – Level 0

```text
                    USER
                     |
                     v
          +----------------------+
          | Cyber Threat         |
          | Detection System     |
          +----------------------+
             |              |
             v              v
         Dataset        Predictions
             |              |
             v              v
        ML Engine        Dashboard

```

---

# 61. Data Flow Diagram – Level 1

```text
Network Dataset
      |
      v
+--------------+
| Preprocessing|
+--------------+
      |
      v
+------------------+
| Feature Selection |
+------------------+
      |
      v
+------------------+
| ML Training       |
+------------------+
      |
      v
+------------------+
| Trained Model     |
+------------------+
      |
      v
New Network Flow
      |
      v
+------------------+
| Prediction Engine |
+------------------+
      |
      v
+------------------+
| Threat / Normal   |
+------------------+
      |
      v
+------------------+
| Dashboard + DB    |
+------------------+

```

---

# 62. Major Project Modules

## Module 1 – Dataset Management

Responsibilities:

- Dataset upload
- Dataset preview
- Dataset validation

## Module 2 – Data Preprocessing

Responsibilities:

- Cleaning
- Encoding
- Scaling
- Missing-value handling

## Module 3 – Unidirectional Flow Processing

Responsibilities:

- One-direction traffic representation
- Directional feature handling

## Module 4 – Feature Engineering

Responsibilities:

- Calculate useful network characteristics
- Remove irrelevant features

## Module 5 – Machine Learning

Responsibilities:

- Model training
- Model testing
- Hyperparameter tuning
- Model comparison

## Module 6 – Threat Detection

Responsibilities:

- Analyze new flows
- Classify traffic
- Calculate confidence

## Module 7 – Risk Engine

Responsibilities:

```text
Low
Medium
High
Critical

```

## Module 8 – Alert Management

Responsibilities:

- Generate alert
- Store alert
- Retrieve alert

## Module 9 – Dashboard

Responsibilities:

- Statistics
- Charts
- Threat details
- Model results

## Module 10 – Reporting

Responsibilities:

- Performance reports
- Threat summaries
- Model comparison

---

# 63. Recommended Folder Structure

```text
ai-unidirectional-threat-detection/
│
├── data/
│   ├── raw/
│   ├── processed/
│   └── sample/
│
├── notebooks/
│   ├── 01_data_analysis.ipynb
│   ├── 02_preprocessing.ipynb
│   ├── 03_feature_engineering.ipynb
│   ├── 04_model_training.ipynb
│   └── 05_model_comparison.ipynb
│
├── src/
│   ├── preprocessing/
│   │   ├── cleaner.py
│   │   ├── encoder.py
│   │   └── scaler.py
│   │
│   ├── features/
│   │   ├── extractor.py
│   │   └── selector.py
│   │
│   ├── models/
│   │   ├── train.py
│   │   ├── evaluate.py
│   │   └── predict.py
│   │
│   ├── security/
│   │   ├── risk_engine.py
│   │   └── alert_engine.py
│   │
│   └── database/
│       └── db.py
│
├── models/
│   ├── random_forest.joblib
│   └── xgboost_model.json
│
├── dashboard/
│   ├── app.py
│   └── pages/
│
├── api/
│   └── main.py
│
├── reports/
│
├── tests/
│
├── requirements.txt
├── README.md
└── .gitignore

```

---

# 64. System Workflow

```text
START
  |
  v
Load Network Dataset
  |
  v
Validate Dataset
  |
  v
Clean Data
  |
  v
Create/Select Unidirectional Features
  |
  v
Feature Engineering
  |
  v
Split Dataset
  |
  v
Train ML Models
  |
  v
Evaluate Models
  |
  v
Select Best Model
  |
  v
Save Model
  |
  v
Receive New Flow
  |
  v
Predict Traffic
  |
  +-----------------------+
  |                       |
NORMAL                  ATTACK
  |                       |
  |                       v
  |                  Classify Attack
  |                       |
  |                       v
  |                   Risk Score
  |                       |
  |                       v
  |                 Generate Alert
  |                       |
  +-----------+-----------+
              |
              v
        Store Result
              |
              v
         Dashboard
              |
              v
             END

```

---

# 65. Risk Classification

Suggested initial risk representation:

| ProbabilityRisk |          |
| --------------- | -------- |
| 0–25%           | Low      |
| 26–50%          | Medium   |
| 51–75%          | High     |
| 76–100%         | Critical |

These thresholds may later be calibrated based on model validation and operational requirements.

---

# 66. Testing Requirements

## Unit Testing

Individual components shall be tested.

Examples:

```text
Dataset loader
Preprocessing
Feature extraction
Prediction
Risk scoring
Database

```

## Integration Testing

Verify:

```text
Dataset → Preprocessing

Preprocessing → Model

Model → Prediction

Prediction → Database

Prediction → Dashboard

```

## System Testing

Test complete end-to-end workflow.

## Performance Testing

Measure:

- Prediction time
- Dataset processing time
- Memory utilization

## Machine Learning Testing

Evaluate using an unseen test set.

---

# 67. Sample Test Cases

## TC-01 – Valid Dataset

**Input:** Correct CSV

**Expected result:** Dataset loads successfully.

---

## TC-02 – Invalid Dataset

**Input:** Unsupported or malformed file

**Expected result:**

```text
Invalid dataset/file-format message.

```

---

## TC-03 – Normal Network Flow

**Input:** Normal flow characteristics

**Expected result:**

```text
Prediction: NORMAL

```

---

## TC-04 – Malicious Flow

**Input:** Known malicious characteristics

**Expected result:**

```text
Prediction: ATTACK
Attack Type: predicted category
Risk Level: calculated level

```

---

## TC-05 – Model Comparison

**Input:** Multiple trained models

**Expected result:**

System displays performance metrics for each model.

---

# 68. Acceptance Criteria

The project shall be considered successfully implemented when:

- Dataset can be loaded.
- Dataset can be preprocessed.
- Unidirectional features can be prepared.
- At least three ML algorithms can be trained.
- At least one trained model can be saved.
- New flows can be classified.
- Threat probability/confidence can be shown where supported.
- Risk level can be generated.
- Threats can be stored.
- Dashboard displays results.
- Model evaluation metrics are produced.
- Unidirectional traffic results can be reported.
- Unidirectional vs bidirectional comparison can be demonstrated where suitable data is available.

---

# 69. Constraints

Potential project limitations include:

- Dataset imbalance
- Missing attack categories
- Limited hardware
- Processing large datasets
- False positives
- False negatives
- Dataset-specific bias
- Concept drift
- Limited visibility when only one traffic direction is available
- Lack of payload information
- Encrypted network traffic
- Differences between research datasets and real-world networks

---

# 70. Assumptions

The project assumes that:

- Training data is legally obtained.
- Dataset labels are reasonably reliable.
- Sufficient computational resources are available.
- Unidirectional flow information contains enough characteristics for useful classification.
- Users operate the system for authorized defensive purposes.

---

# 71. Security Considerations

The application should not automatically trust AI predictions.

Prediction:

```text
HIGH RISK

```

does not automatically mean:

```text
Confirmed Attack

```

Security analysts should be able to review alerts.

The system should therefore be considered:

**AI-assisted cyber-threat detection**

rather than an infallible autonomous security decision maker.

---

# 72. Research Questions

The project can investigate:

### RQ1

How accurately can Machine Learning detect cyber threats using only unidirectional IP-flow information?

### RQ2

Which ML algorithm performs best for unidirectional threat detection?

### RQ3

Which traffic features contribute most strongly to attack detection?

### RQ4

How does unidirectional detection compare with bidirectional detection?

### RQ5

How much does feature selection affect detection performance and prediction time?

---

# 73. Expected Results

The system is expected to:

- Distinguish normal and suspicious traffic.
- Detect selected attack categories.
- Generate useful risk scores.
- Provide visual threat information.
- Demonstrate differences among ML algorithms.
- Evaluate the effect of limited unidirectional traffic visibility.

Exact accuracy values must be obtained experimentally and should not be predetermined.

---

# 74. Advantages

The proposed system provides:

- Automated network threat detection
- AI-based traffic classification
- Detection under limited traffic visibility
- Faster analysis of large flow datasets
- Lower dependence on payload inspection
- Security monitoring of encrypted-flow metadata
- Threat prioritization
- Historical analysis
- Research opportunities
- Extendable architecture
- Low-cost development using open-source tools

---

# 75. Applications

The project may be useful in environments such as:

- Educational institutions
- Corporate networks
- Data centers
- Cloud environments
- Internet Service Providers
- Cybersecurity laboratories
- Research institutions
- SOC environments
- Government networks
- Financial institutions

A production deployment would require stronger testing, governance, privacy controls, monitoring, and integration than the student prototype.

---

# 76. Future Enhancements

Future versions may include:

### 76.1 Real-Time Traffic

```text
Network Interface
        ↓
Zeek
        ↓
Flow Generator
        ↓
AI Model
        ↓
Dashboard

```

### 76.2 Deep Learning

Models such as:

```text
LSTM
Autoencoder
CNN
Transformer

```

### 76.3 Explainable AI

Show:

```text
Why was this flow classified as malicious?

```

Possible tools:

```text
SHAP
Feature Importance

```

### 76.4 Online Learning

Allow the model to adapt to changing traffic patterns.

### 76.5 SIEM Integration

Integrate with enterprise security-monitoring systems.

### 76.6 Email/SMS Alerts

Send alerts for critical threats.

### 76.7 Real-Time API

Create a prediction REST API using FastAPI.

### 76.8 Docker Deployment

Containerize:

```text
AI Model
Backend
Dashboard
Database

```

### 76.9 Cloud Deployment

Deploy the research prototype to an appropriate cloud platform when required.

---

# 77. Development Technology Stack

```text
                PROJECT
                   |
        +----------+----------+
        |                     |
        v                     v
     Python              Cybersecurity
        |                     |
        v                     v
Pandas / NumPy      Wireshark / Zeek
        |
        v
Scikit-learn
        |
        +----------------+
        |                |
        v                v
Random Forest         XGBoost
        |
        v
Trained Model
        |
        v
FastAPI – Optional
        |
        v
Streamlit
        |
        v
SQLite
        |
        v
Dashboard

```

---

# 78. Recommended Final Technology Selection

For the initial implementation:

```text
Language             : Python

IDE                  : VS Code

Experimentation      : Jupyter Notebook

Dataset              : UNSW-NB15

Data Processing      : Pandas + NumPy

Machine Learning     : Scikit-learn

Main Algorithms      : Random Forest + XGBoost

Network Analysis     : Wireshark

Advanced Monitoring  : Zeek

Dashboard            : Streamlit

Database             : SQLite

Backend              : FastAPI – optional initially

Version Control      : Git + GitHub

Deployment           : Docker – final phase

```

---

# 79. Approximate Development Phases

## Phase 1 – Requirement Analysis

- Understand problem
- Finalize dataset
- Identify features

## Phase 2 – Dataset Analysis

- Download dataset
- Understand columns
- Examine labels

## Phase 3 – Preprocessing

- Clean records
- Handle missing data
- Encode categories

## Phase 4 – Uni-flow Preparation

- Select or generate directional information
- Remove reverse-dependent features from the unidirectional experiment

## Phase 5 – Machine Learning

- Logistic Regression
- Decision Tree
- Random Forest
- XGBoost

## Phase 6 – Evaluation

- Accuracy
- Precision
- Recall
- F1
- FPR
- FNR

## Phase 7 – Dashboard

- Build Streamlit UI
- Show detection
- Show analytics

## Phase 8 – Database

- Save predictions
- Save alerts

## Phase 9 – Real-Time Extension

- Wireshark/Zeek integration

## Phase 10 – Final Testing

- Functional testing
- Performance testing
- ML testing

---

# 80. Project Deliverables

The completed project should contain:

- Source code
- Dataset-processing scripts
- Trained ML model
- Streamlit dashboard
- Database
- Test cases
- Model evaluation report
- Research comparison
- SRS document
- Project report
- Architecture diagrams
- PPT presentation
- GitHub repository
- README documentation
- Demo dataset
- Final demonstration

---

# 81. Final Project Abstract

**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic** is a cybersecurity system designed to identify malicious network activities using Machine Learning techniques applied to one-directional network-flow information. The system preprocesses network traffic data, extracts relevant features, trains multiple Machine Learning models, and classifies traffic as normal or malicious. The proposed platform can additionally classify supported attack categories, calculate threat probabilities, generate risk levels, and display security information through an interactive dashboard. Random Forest, XGBoost, Decision Tree, and Logistic Regression can be evaluated using precision, recall, F1-score, false-positive rate, false-negative rate, and other relevant metrics. A key research component compares unidirectional and bidirectional traffic analysis to determine how effectively cyber threats can be identified when complete two-way communication information is unavailable. The system is intended as a low-cost, defensive cybersecurity research prototype and can later be extended with real-time traffic monitoring, explainable AI, SIEM integration, and advanced Machine Learning techniques.

---

# 82. Conclusion

The proposed system provides an intelligent approach for detecting cyber threats using unidirectional IP-traffic information.

The project combines:

```text
Computer Networks
        +
Cybersecurity
        +
Python
        +
Machine Learning
        +
Network Traffic Analysis
        +
Intrusion Detection
        +
Data Science
        +
Dashboard Development

```

The major research contribution is not simply training an intrusion-detection classifier. It is evaluating whether useful cyber-threat detection can still be achieved when the monitoring system has access to only **one direction of network communication**.

This makes the project suitable for academic research, cybersecurity demonstrations, portfolio development, and future extension into real-time network-security monitoring.