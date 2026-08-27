# SRS Traceability Matrix

This matrix links the supplied functional requirements to implemented evidence.

| Requirement | Implementation evidence | Status |
| --- | --- | --- |
| FR-01 Authentication | `auth.py`, `database.py`, dashboard login, `/auth/login` | Complete |
| FR-02 Dataset upload | Dashboard uploader, `/datasets/upload` | Complete for CSV |
| FR-03 Dataset validation | `data.py` file, target, empty, duplicate, missing, numeric checks | Complete |
| FR-04 Preprocessing | Imputation, infinite replacement, encoding, scaling in saved pipeline | Complete |
| FR-05 Uni-flow processing | Explicit reverse-field exclusion in `features.py` | Complete |
| FR-06 Feature extraction/use | Directional flow fields and dataset-driven schema | Complete for structured flows |
| FR-07 Feature selection | Leakage/identity/reverse exclusion and model importance | Complete baseline |
| FR-08 Dataset splitting | Stratified 70/15/15 split | Complete |
| FR-09 Multiple models | Logistic, Decision Tree, Random Forest, XGBoost | Complete |
| FR-10 Model comparison | Accuracy, precision, recall, F1/F2, AUCs, FPR/FNR, timings | Complete |
| FR-11 Best model selection | Weighted security-specific selection score | Complete |
| FR-12 Binary detection | NORMAL/ATTACK saved pipeline | Complete |
| FR-13 Multi-class detection | Separate attack-only category classifier when labels permit | Complete |
| FR-14 Threat probability | `predict_proba`/decision score | Complete |
| FR-15 Risk scoring | `risk.py` LOW/MEDIUM/HIGH/CRITICAL | Complete |
| FR-16 Security alerts | Prediction-to-alert transaction in SQLite | Complete |
| FR-17 Dashboard | Streamlit operational dashboard | Complete |
| FR-18 Threat history | SQLite filters and CSV download | Complete |
| FR-19 Visualization | Distribution, model, matrix, importance, trends | Complete |
| FR-20 Performance report | Saved metadata and JSON evidence report | Complete |
| FR-21 Uni vs bi comparison | Controlled dashboard/service experiment | Complete |
| FR-22 Model saving | Compressed versioned joblib bundle + JSON metadata | Complete |
| FR-23 Prediction module | Cached saved-model inference without retraining | Complete |
| FR-24 Model versioning | Unique version, date, dataset hash, profile, metrics, schema | Complete |
| FR-25 Report generation | Downloadable JSON evidence report and alert CSV | Complete |

Advanced PCAP/Zeek live capture, automated blocking, SIEM integration, cloud deployment, online learning, and deep learning remain deliberately outside version 1, matching the stated scope and future enhancements.

