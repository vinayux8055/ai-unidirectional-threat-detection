# Verification Record

Verification date: 2026-08-27 (UTC)

## Automated checks

```text
15 tests passed
Python modules compiled successfully
Python dependency check: no broken requirements
Streamlit server reached healthy startup
FastAPI health, login, authorization, and analytics routes passed
```

The automated suite covers dataset validation, missing-target rejection, uni-flow reverse-feature exclusion, risk boundaries, password hashing, signed tokens, training, model saving/loading, prediction, database persistence, feature-profile comparison, API health, authentication, and protected-route behavior.

## End-to-end verified path

```text
Synthetic CSV
  → validation and cleaning
  → uni-flow feature selection
  → Logistic Regression + Decision Tree + Random Forest + XGBoost training
  → validation threshold selection
  → unseen test evaluation
  → best-model saving
  → saved-model prediction
  → NORMAL result
  → ATTACK / Reconnaissance / CRITICAL result
  → SQLite alert
  → JSON evidence report
```

## Demonstration-only metrics

The included 5,000-row synthetic dataset produced the following selected-model test result during verification:

| Metric | Result |
| --- | ---: |
| Recall | 0.8447 |
| F1 | 0.7352 |
| ROC-AUC | 0.8823 |
| PR-AUC | 0.9007 |
| False-negative rate | 0.1553 |

These figures prove that the software pipeline works. They are **not final academic accuracy claims** because the dataset is synthetic. Replace them with repeated UNSW-NB15 measurements for the final report.

## Remaining research work

The code implementation is complete for version 1. The student research phase still requires a legally obtained public dataset, documented column semantics, repeated controlled experiments, interpretation of measured results, final screenshots, and institution-specific report/PPT formatting.

