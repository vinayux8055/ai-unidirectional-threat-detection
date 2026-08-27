from __future__ import annotations

import json
import re
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any, Iterable

import numpy as np
import pandas as pd

from .config import Settings, settings
from .data import DatasetValidationError, load_csv, validate_and_clean_frame
from .database import Database
from .features import select_feature_profile
from .models import (
    SUPPORTED_ALGORITHMS,
    ThreatModelBundle,
    load_bundle,
    save_bundle,
    train_models,
)
from .risk import assess_risk


class ThreatDetectionService:
    def __init__(self, app_settings: Settings = settings):
        self.settings = app_settings
        self.settings.ensure_directories()
        self.database = Database(self.settings.database_path)
        self.database.initialize()
        self.database.ensure_admin(
            self.settings.admin_email, self.settings.admin_password
        )
        self._bundle: ThreatModelBundle | None = None
        self._bundle_lock = RLock()

    def validate_dataset(self, path: str | Path) -> dict[str, Any]:
        frame = load_csv(
            path,
            max_bytes=self.settings.max_upload_mb * 1024 * 1024,
        )
        clean, summary = validate_and_clean_frame(frame, require_label=True)
        assert summary is not None
        uni = select_feature_profile(clean, "unidirectional")
        bi = select_feature_profile(clean, "bidirectional")
        return {
            "summary": summary.to_dict(),
            "unidirectional_features": uni.features,
            "bidirectional_features": bi.features,
            "reverse_fields_excluded": uni.excluded_reverse_features,
            "preview": clean.head(20).fillna("").to_dict(orient="records"),
        }

    def store_upload(self, source: str | Path, original_name: str | None = None) -> Path:
        source_path = Path(source).resolve()
        if not source_path.is_file():
            raise DatasetValidationError("Uploaded file is not available.")
        name = _safe_csv_name(original_name or source_path.name)
        timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        destination = (self.settings.uploads_dir / f"{timestamp}_{name}").resolve()
        if self.settings.uploads_dir.resolve() not in destination.parents:
            raise DatasetValidationError("Unsafe upload path.")
        if source_path.stat().st_size > self.settings.max_upload_mb * 1024 * 1024:
            raise DatasetValidationError("Uploaded dataset exceeds the size limit.")
        shutil.copy2(source_path, destination)
        return destination

    def train(
        self,
        dataset_path: str | Path,
        *,
        profile_name: str = "unidirectional",
        algorithms: Iterable[str] = SUPPORTED_ALGORITHMS,
        activate: bool = True,
        actor: str = "local-user",
    ) -> dict[str, Any]:
        frame = load_csv(
            dataset_path,
            max_bytes=self.settings.max_upload_mb * 1024 * 1024,
        )
        clean, summary = validate_and_clean_frame(frame, require_label=True)
        assert summary is not None
        profile = select_feature_profile(clean, profile_name)
        bundle, comparison = train_models(
            clean,
            summary,
            profile,
            algorithms=algorithms,
            random_state=self.settings.random_state,
            max_rows=self.settings.max_training_rows,
        )
        artifact = save_bundle(bundle, self.settings.models_dir)
        self.database.add_dataset(Path(dataset_path).name, str(dataset_path), summary.to_dict())
        self.database.add_model(bundle.metadata(), str(artifact), activate=activate)
        if activate:
            with self._bundle_lock:
                self._bundle = bundle
        self.database.audit(
            actor,
            "MODEL_TRAINED",
            {
                "version": bundle.version,
                "profile": profile_name,
                "dataset_sha256": summary.sha256,
            },
        )
        return {
            "artifact": str(artifact),
            "model": bundle.metadata(),
            "comparison": comparison,
            "dataset": summary.to_dict(),
        }

    def compare_unidirectional_bidirectional(
        self,
        dataset_path: str | Path,
        *,
        algorithms: Iterable[str] = ("random_forest",),
        actor: str = "local-user",
    ) -> dict[str, Any]:
        uni = self.train(
            dataset_path,
            profile_name="unidirectional",
            algorithms=algorithms,
            activate=True,
            actor=actor,
        )
        bi = self.train(
            dataset_path,
            profile_name="bidirectional",
            algorithms=algorithms,
            activate=False,
            actor=actor,
        )
        return {
            "unidirectional": uni,
            "bidirectional": bi,
            "comparison": _profile_comparison(uni, bi),
            "research_note": (
                "Results are comparable because both profiles use the same split policy and random seed. "
                "The unidirectional profile excludes detected reverse-direction fields."
            ),
        }

    def load_active_bundle(self, *, force_reload: bool = False) -> ThreatModelBundle:
        with self._bundle_lock:
            if self._bundle is not None and not force_reload:
                return self._bundle
            model_row = self.database.get_active_model()
            if not model_row:
                raise RuntimeError("No active model. Train a model first.")
            artifact = Path(model_row["artifact_path"]).resolve()
            if self.settings.models_dir.resolve() not in artifact.parents:
                raise RuntimeError("Active model path is outside the trusted model directory.")
            self._bundle = load_bundle(artifact)
            return self._bundle

    def predict_frame(
        self,
        frame: pd.DataFrame,
        *,
        persist: bool = True,
    ) -> list[dict[str, Any]]:
        clean, _ = validate_and_clean_frame(frame, require_label=False)
        bundle = self.load_active_bundle()
        required = list(bundle.profile["features"])
        missing = sorted(set(required) - set(clean.columns))
        if missing:
            raise DatasetValidationError(
                "Prediction input is missing required fields: " + ", ".join(missing[:20])
            )
        values = clean.reindex(columns=required)

        start = time.perf_counter()
        probabilities = _positive_probabilities(bundle.binary_model, values)
        elapsed_ms = (time.perf_counter() - start) * 1000
        latency_per_row = elapsed_ms / max(len(values), 1)
        binary = (probabilities >= bundle.threshold).astype(int)

        attack_names = np.full(len(values), "Normal", dtype=object)
        attack_confidence = np.zeros(len(values), dtype=float)
        attack_indices = np.where(binary == 1)[0]
        if len(attack_indices) and bundle.attack_model is not None:
            attack_values = values.iloc[attack_indices]
            encoded = bundle.attack_model.predict(attack_values).astype(int)
            assert bundle.attack_label_encoder is not None
            attack_names[attack_indices] = bundle.attack_label_encoder.inverse_transform(encoded)
            if hasattr(bundle.attack_model, "predict_proba"):
                attack_confidence[attack_indices] = np.max(
                    bundle.attack_model.predict_proba(attack_values), axis=1
                )
        elif len(attack_indices):
            attack_names[attack_indices] = "Attack"

        results: list[dict[str, Any]] = []
        original = clean.to_dict(orient="records")
        for index, probability in enumerate(probabilities):
            risk = assess_risk(float(probability))
            result = {
                "prediction": "ATTACK" if binary[index] else "NORMAL",
                "attack_type": str(attack_names[index]),
                "attack_class_confidence": round(float(attack_confidence[index]), 6),
                "threat_probability": round(float(probability), 6),
                "risk_score": risk.score,
                "risk_level": risk.level,
                "threshold": bundle.threshold,
                "model_name": bundle.model_name,
                "model_version": bundle.version,
                "profile": bundle.profile["name"],
                "latency_ms": round(latency_per_row, 6),
                "top_model_features": bundle.feature_importance[:5],
            }
            if persist:
                ids = self.database.record_prediction(original[index], result)
                result.update(ids)
            results.append(result)
        return results

    def predict_one(self, flow: dict[str, Any], *, persist: bool = True) -> dict[str, Any]:
        return self.predict_frame(pd.DataFrame([flow]), persist=persist)[0]

    def model_performance(self) -> dict[str, Any]:
        return self.load_active_bundle().metadata()

    def create_report(self) -> Path:
        bundle = self.load_active_bundle()
        report = {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "system": self.settings.app_name,
            "model": bundle.metadata(),
            "operational_analytics": self.database.analytics(),
            "alerts": self.database.list_alerts(limit=100),
            "limitations": [
                "Predictions are AI-assisted indicators and require analyst review.",
                "Performance on a synthetic demo dataset is not evidence of real-world accuracy.",
                "Concept drift and changes in network behavior require periodic re-evaluation.",
            ],
        }
        path = self.settings.reports_dir / f"threat_report_{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.json"
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return path


def _positive_probabilities(model: Any, frame: pd.DataFrame) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(frame)
        classes = list(model.classes_)
        index = classes.index(1) if 1 in classes else -1
        return np.asarray(probabilities[:, index], dtype=float)
    scores = np.asarray(model.decision_function(frame), dtype=float)
    return 1.0 / (1.0 + np.exp(-np.clip(scores, -40, 40)))


def _safe_csv_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name).name)
    if not cleaned.lower().endswith(".csv"):
        raise DatasetValidationError("Only .csv uploads are allowed.")
    return cleaned[:120]


def _profile_comparison(uni: dict[str, Any], bi: dict[str, Any]) -> list[dict[str, Any]]:
    uni_metrics = uni["model"]["metrics"]["test"]
    bi_metrics = bi["model"]["metrics"]["test"]
    keys = (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "roc_auc",
        "pr_auc",
        "false_positive_rate",
        "false_negative_rate",
        "prediction_ms_per_1000",
    )
    return [
        {
            "metric": key,
            "unidirectional": uni_metrics.get(key),
            "bidirectional": bi_metrics.get(key),
        }
        for key in keys
    ]


service = ThreatDetectionService()

