from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from scripts.generate_demo_data import generate
from threatguard.auth import create_access_token, decode_access_token, hash_password, verify_password
from threatguard.config import Settings
from threatguard.data import DatasetValidationError, validate_and_clean_frame
from threatguard.features import select_feature_profile
from threatguard.risk import assess_risk
from threatguard.service import ThreatDetectionService


def test_dataset_validation_and_targets() -> None:
    frame = generate(300, 7)
    clean, summary = validate_and_clean_frame(frame)
    assert summary is not None
    assert summary.rows == 300
    assert summary.normal_rows > 0
    assert summary.attack_rows > 0
    assert set(clean[summary.label_column].unique()) == {0, 1}


def test_missing_target_rejected() -> None:
    frame = pd.DataFrame({"packets": [1] * 30, "bytes": [100] * 30})
    with pytest.raises(DatasetValidationError, match="Missing target"):
        validate_and_clean_frame(frame)


def test_unidirectional_profile_removes_reverse_and_identity_fields() -> None:
    clean, _ = validate_and_clean_frame(generate(250, 3))
    profile = select_feature_profile(clean, "unidirectional")
    assert "spkts" in profile.features
    assert "sbytes" in profile.features
    assert "dpkts" not in profile.features
    assert "dbytes" not in profile.features
    assert "src_ip" not in profile.features
    assert "label" not in profile.features
    assert "attack_cat" not in profile.features


@pytest.mark.parametrize(
    ("probability", "expected"),
    [(0.0, "LOW"), (0.25, "LOW"), (0.26, "MEDIUM"), (0.51, "HIGH"), (0.76, "CRITICAL"), (1.0, "CRITICAL")],
)
def test_risk_boundaries(probability: float, expected: str) -> None:
    assert assess_risk(probability).level == expected


def test_password_hash_and_token_round_trip() -> None:
    encoded = hash_password("ReliablePassword123!")
    assert verify_password("ReliablePassword123!", encoded)
    assert not verify_password("incorrect-value", encoded)
    token = create_access_token("analyst@example.com", "researcher", "unit-test-secret")
    payload = decode_access_token(token, "unit-test-secret")
    assert payload["sub"] == "analyst@example.com"
    with pytest.raises(ValueError):
        decode_access_token(token, "wrong-secret")


def _test_settings(tmp_path: Path) -> Settings:
    return Settings(
        app_name="Test ThreatGuard",
        app_secret="unit-test-secret",
        admin_email="admin@example.com",
        admin_password="AdminPassword123!",
        max_upload_mb=20,
        max_training_rows=2000,
        random_state=42,
        root=tmp_path,
        data_dir=tmp_path / "data",
        uploads_dir=tmp_path / "data" / "uploads",
        sample_dir=tmp_path / "data" / "sample",
        models_dir=tmp_path / "models",
        reports_dir=tmp_path / "reports",
        database_path=tmp_path / "test.db",
    )


def test_end_to_end_training_prediction_and_alert(tmp_path: Path) -> None:
    app_settings = _test_settings(tmp_path)
    service = ThreatDetectionService(app_settings)
    dataset = app_settings.sample_dir / "flows.csv"
    generate(800, 42).to_csv(dataset, index=False)

    trained = service.train(
        dataset,
        profile_name="unidirectional",
        algorithms=["logistic_regression", "decision_tree"],
        actor="pytest",
    )
    assert trained["model"]["profile"]["name"] == "unidirectional"
    assert trained["model"]["metrics"]["test"]["recall"] >= 0.60
    assert Path(trained["artifact"]).exists()

    source = generate(1, 999).drop(columns=["label", "attack_cat"])
    result = service.predict_frame(source, persist=True)[0]
    assert result["prediction"] in {"NORMAL", "ATTACK"}
    assert 0 <= result["threat_probability"] <= 1
    assert result["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert result["prediction_id"] > 0
    assert service.database.analytics()["totals"]["total"] == 1


def test_controlled_uni_bi_feature_counts(tmp_path: Path) -> None:
    app_settings = _test_settings(tmp_path)
    service = ThreatDetectionService(app_settings)
    dataset = app_settings.sample_dir / "flows.csv"
    generate(500, 18).to_csv(dataset, index=False)
    validation = service.validate_dataset(dataset)
    assert len(validation["unidirectional_features"]) < len(validation["bidirectional_features"])
    assert "dpkts" in validation["reverse_fields_excluded"]

