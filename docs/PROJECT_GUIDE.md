# Final-Year Project Guide

## 1. Research contribution

The project is not merely an intrusion-detection classifier. Its central experiment asks whether useful detection remains possible when only source-to-destination flow characteristics are visible. The bidirectional model is a controlled baseline, not the primary result.

## 2. Correct experiment design

Use the same dataset snapshot, cleaning rules, random seed, split ratios, algorithm, and hyperparameters for the uni-flow and bi-flow experiments. Change only the feature profile. Record the exact excluded reverse fields in the report.

The implemented split is:

| Partition | Purpose | Share |
| --- | --- | ---: |
| Training | Fit preprocessing and model parameters | 70% |
| Validation | Choose the threat threshold | 15% |
| Test | Final unbiased measurement | 15% |

The default threshold is chosen by validation-set F2 because missed attacks are costly. The test set is not used to select the threshold or model.

## 3. Metrics to report

Do not select the winner by accuracy alone. Present:

- Accuracy
- Precision
- Recall or detection rate
- F1 and F2
- PR-AUC and ROC-AUC
- False-positive rate
- False-negative rate
- Confusion matrix
- Training time
- Prediction time per 1,000 flows
- Per-class recall and macro F1 for the attack-category model

For an imbalanced threat dataset, PR-AUC, recall, F1, FPR, and FNR are usually more informative than accuracy.

## 4. Accuracy improvement checklist

1. Use the official public dataset, not the synthetic demo, for final numbers.
2. Verify every column meaning from the dataset documentation.
3. Add any differently named reverse field to the explicit exclusion list.
4. Remove target leakage, flow identifiers, IP identities, and timestamps from random-split training.
5. Compare stratified random split with a time-aware or source-aware split.
6. Inspect class imbalance before applying class weighting or sampling.
7. Tune one model at a time with validation data or cross-validation.
8. Check false negatives per attack category.
9. Repeat with seeds such as 21, 42, and 84 and report mean ± standard deviation.
10. Test against a second dataset or small authorized lab capture for external validity.
11. Calibrate probabilities before treating them as operational confidence.
12. Re-evaluate after traffic behavior changes; this is concept-drift monitoring.

## 5. Performance improvement checklist

- Use the `MAX_TRAINING_ROWS` safety setting during development.
- Keep categorical fields low-cardinality; do not one-hot encode raw IP addresses.
- Use Random Forest or XGBoost for the final comparison and Logistic Regression as a transparent baseline.
- Batch predictions instead of calling the model once per row.
- Keep the saved pipeline loaded in memory; ThreatGuard caches the active bundle.
- Use SSD storage and 16 GB RAM for the full UNSW-NB15 experiment.
- Measure before optimizing. Record preprocessing, training, and inference separately.

## 6. Security and ethics

- Analyze only legally obtained datasets and authorized traffic.
- Prefer metadata; do not collect unnecessary packet payloads.
- Change default credentials and the signing secret.
- Do not expose the development dashboard directly to the public Internet.
- Do not load model files supplied by untrusted users because pickle/joblib artifacts can execute code.
- Retain IP addresses only when necessary and permitted.
- Treat predictions as analyst-review signals.

## 7. Demonstration script

1. Explain the one-way visibility problem with source → destination traffic.
2. Log in and upload the dataset.
3. Show validation, label counts, missing values, and excluded reverse fields.
4. Train Logistic Regression, Decision Tree, Random Forest, and XGBoost.
5. Explain why the best model is chosen with recall/F1/FNR, not accuracy only.
6. Show the untouched test confusion matrix and inference time.
7. Run the controlled uni-vs-bi experiment.
8. Analyze a batch of new flows.
9. Open a critical alert and show history/analytics.
10. Generate the evidence report.
11. Finish with limitations and future Zeek/IPFIX ingestion.

## 8. Screenshots to capture for the report

- Login page
- Dataset validation summary
- Class-distribution chart
- Reverse-field exclusion message
- Model comparison table
- Confusion matrix
- Feature-importance chart
- Uni-flow vs bi-flow comparison
- Normal prediction
- Attack prediction and created alert
- Threat history filters
- Analytics dashboard
- API documentation page
- Docker containers running
- Automated tests passing

## 9. Results table template

Replace every placeholder with measured values. Never invent scores.

| Model | Profile | Accuracy | Precision | Recall | F1 | PR-AUC | FPR | FNR | ms/1,000 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Logistic Regression | Uni | Result | Result | Result | Result | Result | Result | Result | Result |
| Decision Tree | Uni | Result | Result | Result | Result | Result | Result | Result | Result |
| Random Forest | Uni | Result | Result | Result | Result | Result | Result | Result | Result |
| XGBoost | Uni | Result | Result | Result | Result | Result | Result | Result | Result |
| Best matched model | Bi | Result | Result | Result | Result | Result | Result | Result | Result |

## 10. Viva questions

**Why unidirectional traffic?** Monitoring points, asymmetric routing, exporters, and constrained environments may expose only one direction of a conversation.

**Why not accuracy alone?** A highly imbalanced dataset can produce high accuracy while missing many attacks.

**What is data leakage?** Information unavailable during real prediction—or information that directly reveals the label—accidentally enters model training and inflates scores.

**Why use validation and test sets?** Validation selects the model and threshold; the untouched test set estimates generalization.

**Why save preprocessing with the model?** Prediction must apply exactly the same imputation, scaling, encoding, feature order, and unknown-category handling used during training.

**Why can synthetic accuracy not be claimed?** Synthetic patterns were generated by known rules and do not represent the diversity, noise, bias, and drift of real networks.

**What causes false positives?** Rare legitimate behavior can resemble attacks, dataset labels can be noisy, and production traffic can differ from training data.

**What causes false negatives?** Limited visibility, new attack behavior, weak features, class imbalance, concept drift, and inappropriate thresholds.

**Is a probability a guarantee?** No. It is a model score that should be calibrated and interpreted with operational context.

**How can the project become real-time?** Convert authorized Zeek, NetFlow, or IPFIX records into the saved feature schema, batch them through the prediction API, and forward reviewed alerts to a SIEM.

