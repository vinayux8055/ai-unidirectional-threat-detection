from __future__ import annotations

import json
import math
import os
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    fbeta_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

from .data import DatasetSummary
from .features import FeatureProfile


SUPPORTED_ALGORITHMS = (
    "logistic_regression",
    "decision_tree",
    "random_forest",
    "xgboost",
)


@dataclass
class ThreatModelBundle:
    version: str
    model_name: str
    engine: str
    created_at: str
    profile: dict[str, Any]
    dataset_sha256: str
    threshold: float
    binary_model: Pipeline
    attack_model: Pipeline | None
    attack_label_encoder: LabelEncoder | None
    metrics: dict[str, Any]
    feature_importance: list[dict[str, Any]]

    def metadata(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "model_name": self.model_name,
            "engine": self.engine,
            "created_at": self.created_at,
            "profile": self.profile,
            "dataset_sha256": self.dataset_sha256,
            "threshold": self.threshold,
            "metrics": self.metrics,
            "feature_importance": self.feature_importance,
            "has_attack_classifier": self.attack_model is not None,
            "attack_classes": (
                self.attack_label_encoder.classes_.tolist()
                if self.attack_label_encoder is not None
                else []
            ),
        }


def _preprocessor(profile: FeatureProfile) -> ColumnTransformer:
    transformers: list[tuple[str, Pipeline, list[str]]] = []
    if profile.numeric_features:
        numeric = Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
            ]
        )
        transformers.append(("numeric", numeric, profile.numeric_features))
    if profile.categorical_features:
        categorical = Pipeline(
            [
                ("imputer", SimpleImputer(strategy="most_frequent")),
                (
                    "encoder",
                    OneHotEncoder(
                        handle_unknown="ignore",
                        min_frequency=2,
                        sparse_output=False,
                    ),
                ),
            ]
        )
        transformers.append(("categorical", categorical, profile.categorical_features))
    return ColumnTransformer(transformers=transformers, remainder="drop")


def _estimator(name: str, random_state: int) -> tuple[BaseEstimator, str]:
    if name == "logistic_regression":
        return (
            LogisticRegression(
                max_iter=700,
                class_weight="balanced",
                solver="lbfgs",
                random_state=random_state,
            ),
            "scikit-learn LogisticRegression",
        )
    if name == "decision_tree":
        return (
            DecisionTreeClassifier(
                max_depth=24,
                min_samples_leaf=3,
                class_weight="balanced",
                random_state=random_state,
            ),
            "scikit-learn DecisionTreeClassifier",
        )
    if name == "random_forest":
        return (
            RandomForestClassifier(
                n_estimators=220,
                max_depth=28,
                min_samples_leaf=2,
                max_features="sqrt",
                class_weight="balanced_subsample",
                n_jobs=-1,
                random_state=random_state,
            ),
            "scikit-learn RandomForestClassifier",
        )
    if name == "xgboost":
        try:
            from xgboost import XGBClassifier

            return (
                XGBClassifier(
                    n_estimators=260,
                    max_depth=7,
                    learning_rate=0.07,
                    subsample=0.85,
                    colsample_bytree=0.85,
                    reg_lambda=1.5,
                    objective="binary:logistic",
                    eval_metric="logloss",
                    n_jobs=max(1, (os.cpu_count() or 2) - 1),
                    random_state=random_state,
                ),
                "xgboost XGBClassifier",
            )
        except ImportError:
            return (
                HistGradientBoostingClassifier(
                    max_iter=220,
                    learning_rate=0.08,
                    max_leaf_nodes=31,
                    l2_regularization=1.0,
                    random_state=random_state,
                ),
                "scikit-learn HistGradientBoosting fallback (install xgboost for XGBoost)",
            )
    raise ValueError(f"Unsupported algorithm: {name}")


def build_pipeline(name: str, profile: FeatureProfile, random_state: int) -> tuple[Pipeline, str]:
    estimator, engine = _estimator(name, random_state)
    return Pipeline([("preprocess", _preprocessor(profile)), ("model", estimator)]), engine


def _positive_probabilities(model: Pipeline, values: pd.DataFrame) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(values)
        classes = list(model.classes_)
        positive_index = classes.index(1) if 1 in classes else -1
        return np.asarray(probabilities[:, positive_index], dtype=float)
    if hasattr(model, "decision_function"):
        scores = np.asarray(model.decision_function(values), dtype=float)
        return 1.0 / (1.0 + np.exp(-np.clip(scores, -40, 40)))
    return np.asarray(model.predict(values), dtype=float)


def choose_threshold(y_true: pd.Series, probabilities: np.ndarray) -> float:
    best_threshold = 0.5
    best_score = -1.0
    # F2 weights missed attacks more strongly than false alarms.
    for threshold in np.linspace(0.15, 0.85, 71):
        predictions = (probabilities >= threshold).astype(int)
        score = fbeta_score(y_true, predictions, beta=2, zero_division=0)
        if score > best_score or (
            math.isclose(score, best_score) and abs(threshold - 0.5) < abs(best_threshold - 0.5)
        ):
            best_score = float(score)
            best_threshold = float(threshold)
    return round(best_threshold, 3)


def binary_metrics(
    y_true: Iterable[int],
    probabilities: np.ndarray,
    threshold: float,
) -> dict[str, Any]:
    true = np.asarray(list(y_true), dtype=int)
    predicted = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(true, predicted, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0
    metrics = {
        "accuracy": accuracy_score(true, predicted),
        "precision": precision_score(true, predicted, zero_division=0),
        "recall": recall_score(true, predicted, zero_division=0),
        "f1": f1_score(true, predicted, zero_division=0),
        "f2": fbeta_score(true, predicted, beta=2, zero_division=0),
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "threshold": threshold,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "test_samples": len(true),
    }
    if len(np.unique(true)) == 2:
        metrics["roc_auc"] = roc_auc_score(true, probabilities)
        metrics["pr_auc"] = average_precision_score(true, probabilities)
    return _json_safe(metrics)


def _model_score(metrics: dict[str, Any]) -> float:
    # Recall and F1 dominate; FPR and prediction time provide tie-breaking pressure.
    latency_penalty = min(float(metrics.get("prediction_ms_per_1000", 0)) / 5000, 0.05)
    return (
        0.38 * float(metrics["recall"])
        + 0.32 * float(metrics["f1"])
        + 0.16 * float(metrics.get("pr_auc", metrics["f1"]))
        + 0.08 * (1.0 - float(metrics["false_negative_rate"]))
        + 0.06 * (1.0 - float(metrics["false_positive_rate"]))
        - latency_penalty
    )


def _stratified_sample(
    frame: pd.DataFrame,
    y: pd.Series,
    max_rows: int,
    random_state: int,
) -> tuple[pd.DataFrame, pd.Series]:
    if len(frame) <= max_rows:
        return frame, y
    sampled, _, sampled_y, _ = train_test_split(
        frame,
        y,
        train_size=max_rows,
        stratify=y,
        random_state=random_state,
    )
    return sampled, sampled_y


def _split_three_way(
    values: pd.DataFrame,
    target: pd.Series,
    random_state: int,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.Series]:
    x_train, x_temp, y_train, y_temp = train_test_split(
        values,
        target,
        test_size=0.30,
        stratify=target,
        random_state=random_state,
    )
    x_validation, x_test, y_validation, y_test = train_test_split(
        x_temp,
        y_temp,
        test_size=0.50,
        stratify=y_temp,
        random_state=random_state,
    )
    return x_train, x_validation, x_test, y_train, y_validation, y_test


def _feature_importance(model: Pipeline, limit: int = 20) -> list[dict[str, Any]]:
    estimator = model.named_steps["model"]
    values = getattr(estimator, "feature_importances_", None)
    if values is None:
        coefficients = getattr(estimator, "coef_", None)
        if coefficients is not None:
            values = np.abs(np.asarray(coefficients)[0])
    if values is None:
        return []
    try:
        names = model.named_steps["preprocess"].get_feature_names_out()
    except (AttributeError, ValueError):
        names = [f"feature_{index}" for index in range(len(values))]
    pairs = sorted(zip(names, values), key=lambda item: float(item[1]), reverse=True)
    return [
        {"feature": str(name), "importance": round(float(value), 8)}
        for name, value in pairs[:limit]
    ]


def _attack_classifier(
    algorithm: str,
    profile: FeatureProfile,
    x_train: pd.DataFrame,
    attack_names: pd.Series,
    random_state: int,
) -> tuple[Pipeline | None, LabelEncoder | None]:
    counts = attack_names.value_counts()
    valid_classes = counts[counts >= 3].index
    mask = attack_names.isin(valid_classes)
    if len(valid_classes) < 2 or int(mask.sum()) < 20:
        return None, None

    encoder = LabelEncoder()
    encoded = encoder.fit_transform(attack_names.loc[mask].astype(str))
    pipeline, _ = build_pipeline(algorithm, profile, random_state)
    estimator = pipeline.named_steps["model"]
    # XGBoost needs a multiclass objective; other estimators infer it.
    if estimator.__class__.__name__ == "XGBClassifier":
        estimator.set_params(objective="multi:softprob", num_class=len(encoder.classes_))
    pipeline.fit(x_train.loc[mask], encoded)
    return pipeline, encoder


def train_models(
    frame: pd.DataFrame,
    summary: DatasetSummary,
    profile: FeatureProfile,
    *,
    algorithms: Iterable[str] = SUPPORTED_ALGORITHMS,
    random_state: int = 42,
    max_rows: int = 250_000,
) -> tuple[ThreatModelBundle, list[dict[str, Any]]]:
    names = list(dict.fromkeys(algorithms))
    invalid = sorted(set(names) - set(SUPPORTED_ALGORITHMS))
    if invalid:
        raise ValueError(f"Unsupported algorithms: {invalid}")
    if not names:
        raise ValueError("Select at least one algorithm.")

    x = frame[profile.features].copy()
    y = frame[summary.label_column].astype(int)
    x, y = _stratified_sample(x, y, max_rows=max_rows, random_state=random_state)
    attack_labels = (
        frame.loc[x.index, summary.attack_column].astype(str).reset_index(drop=True)
        if summary.attack_column
        else None
    )
    x_train, x_validation, x_test, y_train, y_validation, y_test = _split_three_way(
        x, y, random_state
    )

    comparison: list[dict[str, Any]] = []
    trained: dict[str, tuple[Pipeline, str, float, dict[str, Any]]] = {}
    for name in names:
        pipeline, engine = build_pipeline(name, profile, random_state)
        fit_start = time.perf_counter()
        pipeline.fit(x_train, y_train)
        training_seconds = time.perf_counter() - fit_start

        validation_probability = _positive_probabilities(pipeline, x_validation)
        threshold = choose_threshold(y_validation, validation_probability)
        predict_start = time.perf_counter()
        test_probability = _positive_probabilities(pipeline, x_test)
        prediction_seconds = time.perf_counter() - predict_start

        metrics = binary_metrics(y_test, test_probability, threshold)
        metrics.update(
            {
                "training_seconds": round(training_seconds, 6),
                "prediction_seconds": round(prediction_seconds, 6),
                "prediction_ms_per_1000": round(
                    (prediction_seconds / max(len(x_test), 1)) * 1_000_000, 6
                ),
                "engine": engine,
                "selection_score": 0.0,
            }
        )
        metrics["selection_score"] = round(_model_score(metrics), 8)
        row = {"model": name, **metrics}
        comparison.append(row)
        trained[name] = (pipeline, engine, threshold, metrics)

    comparison.sort(key=lambda row: row["selection_score"], reverse=True)
    best_name = str(comparison[0]["model"])
    binary_model, engine, threshold, best_metrics = trained[best_name]

    attack_model: Pipeline | None = None
    attack_encoder: LabelEncoder | None = None
    if attack_labels is not None:
        # Use only the training partition indices to keep test data unseen.
        training_attack_names = attack_labels.loc[x_train.index]
        attack_mask = y_train == 1
        attack_model, attack_encoder = _attack_classifier(
            best_name,
            profile,
            x_train.loc[attack_mask],
            training_attack_names.loc[attack_mask],
            random_state,
        )

    created_at = datetime.now(UTC).isoformat(timespec="seconds")
    version = datetime.now(UTC).strftime("v%Y%m%d-%H%M%S-%f")
    metrics_payload = {
        "best_model": best_name,
        "test": best_metrics,
        "comparison": comparison,
        "split": {"training": 0.70, "validation": 0.15, "testing": 0.15},
        "training_rows_used": len(x),
        "selection_policy": "weighted recall, F1, PR-AUC, FNR, FPR, and latency",
    }
    bundle = ThreatModelBundle(
        version=version,
        model_name=best_name,
        engine=engine,
        created_at=created_at,
        profile=profile.to_dict(),
        dataset_sha256=summary.sha256,
        threshold=threshold,
        binary_model=binary_model,
        attack_model=attack_model,
        attack_label_encoder=attack_encoder,
        metrics=_json_safe(metrics_payload),
        feature_importance=_feature_importance(binary_model),
    )
    return bundle, comparison


def save_bundle(bundle: ThreatModelBundle, directory: str | Path) -> Path:
    target_dir = Path(directory)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{bundle.version}_{bundle.profile['name']}.joblib"
    temporary = target.with_suffix(".tmp")
    joblib.dump(bundle, temporary, compress=3)
    temporary.replace(target)
    metadata_path = target.with_suffix(".json")
    metadata_path.write_text(
        json.dumps(bundle.metadata(), indent=2, sort_keys=True), encoding="utf-8"
    )
    return target


def load_bundle(path: str | Path) -> ThreatModelBundle:
    artifact = Path(path).resolve()
    if artifact.suffix.lower() != ".joblib" or not artifact.is_file():
        raise ValueError("A valid local .joblib model artifact is required.")
    loaded = joblib.load(artifact)
    if not isinstance(loaded, ThreatModelBundle):
        raise ValueError("The model artifact has an unsupported format.")
    return loaded


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    return value
