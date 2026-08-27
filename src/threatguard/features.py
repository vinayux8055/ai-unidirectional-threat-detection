from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from .data import ATTACK_ALIASES, LABEL_ALIASES, UNSAFE_ID_COLUMNS


# UNSW-NB15 destination/reverse-direction features plus common aliases.
REVERSE_DEPENDENT_FEATURES = {
    "dpkts",
    "dbytes",
    "dttl",
    "dload",
    "dloss",
    "dinpkt",
    "djit",
    "dwin",
    "dtcpb",
    "tcprtt",
    "synack",
    "ackdat",
    "dmean",
    "response_body_len",
    "dst_packets",
    "destination_packets",
    "reverse_packet_count",
    "dst_bytes",
    "destination_bytes",
    "reverse_byte_count",
    "backward_packets",
    "backward_bytes",
    "bwd_packets",
    "bwd_bytes",
    "bwd_packet_length_mean",
    "bwd_iat_mean",
}


@dataclass(frozen=True)
class FeatureProfile:
    name: str
    features: list[str]
    numeric_features: list[str]
    categorical_features: list[str]
    excluded_reverse_features: list[str]
    excluded_identity_features: list[str]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "features": self.features,
            "numeric_features": self.numeric_features,
            "categorical_features": self.categorical_features,
            "excluded_reverse_features": self.excluded_reverse_features,
            "excluded_identity_features": self.excluded_identity_features,
        }


def select_feature_profile(frame: pd.DataFrame, mode: str = "unidirectional") -> FeatureProfile:
    mode = mode.strip().lower()
    if mode not in {"unidirectional", "bidirectional"}:
        raise ValueError("Feature mode must be 'unidirectional' or 'bidirectional'.")

    targets = set(LABEL_ALIASES) | set(ATTACK_ALIASES)
    candidates = [column for column in frame.columns if column not in targets]
    excluded_identity = sorted(c for c in candidates if c in UNSAFE_ID_COLUMNS)
    candidates = [c for c in candidates if c not in UNSAFE_ID_COLUMNS]

    excluded_reverse: list[str] = []
    if mode == "unidirectional":
        excluded_reverse = sorted(c for c in candidates if c in REVERSE_DEPENDENT_FEATURES)
        candidates = [c for c in candidates if c not in REVERSE_DEPENDENT_FEATURES]

    # Completely empty columns carry no information and can break imputers.
    candidates = [c for c in candidates if not frame[c].isna().all()]
    numeric = [c for c in candidates if pd.api.types.is_numeric_dtype(frame[c])]
    categorical = [c for c in candidates if c not in numeric]

    if len(candidates) < 2:
        raise ValueError("At least two usable, non-target flow features are required.")
    return FeatureProfile(
        name=mode,
        features=candidates,
        numeric_features=numeric,
        categorical_features=categorical,
        excluded_reverse_features=excluded_reverse,
        excluded_identity_features=excluded_identity,
    )

