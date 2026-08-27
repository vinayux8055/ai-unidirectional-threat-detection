from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd


LABEL_ALIASES = ("label", "target", "is_attack", "binary_label")
ATTACK_ALIASES = ("attack_cat", "attack_category", "attack_type", "category")
NORMAL_NAMES = {"normal", "benign", "0", "false", "none"}
UNSAFE_ID_COLUMNS = {
    "id",
    "flow_id",
    "srcip",
    "dstip",
    "src_ip",
    "dst_ip",
    "source_ip",
    "destination_ip",
    "timestamp",
    "start_time",
    "end_time",
    "stime",
    "ltime",
}


class DatasetValidationError(ValueError):
    """Raised when a network-flow dataset cannot safely be used."""


@dataclass(frozen=True)
class DatasetSummary:
    rows: int
    columns: int
    duplicate_rows_removed: int
    missing_values: int
    infinite_values_replaced: int
    label_column: str
    attack_column: str | None
    normal_rows: int
    attack_rows: int
    class_distribution: dict[str, int]
    sha256: str

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_column_name(value: object) -> str:
    name = str(value).strip().lower()
    name = re.sub(r"[^a-z0-9]+", "_", name)
    return name.strip("_")


def normalize_columns(frame: pd.DataFrame) -> pd.DataFrame:
    result = frame.copy()
    normalized = [normalize_column_name(c) for c in result.columns]
    if len(normalized) != len(set(normalized)):
        duplicates = sorted({c for c in normalized if normalized.count(c) > 1})
        raise DatasetValidationError(
            f"Column names become duplicated after normalization: {duplicates}"
        )
    result.columns = normalized
    return result


def _first_present(columns: Iterable[str], aliases: Iterable[str]) -> str | None:
    available = set(columns)
    return next((name for name in aliases if name in available), None)


def _binary_target(series: pd.Series) -> pd.Series:
    if pd.api.types.is_numeric_dtype(series):
        numeric = pd.to_numeric(series, errors="coerce")
        if numeric.isna().any():
            raise DatasetValidationError("The binary label contains invalid values.")
        unique = set(numeric.astype(int).unique())
        if not unique.issubset({0, 1}):
            raise DatasetValidationError(
                f"Binary label must contain only 0 and 1; received {sorted(unique)}."
            )
        return numeric.astype("int8")

    normalized = series.astype(str).str.strip().str.lower()
    return (~normalized.isin(NORMAL_NAMES)).astype("int8")


def _sha256_frame(frame: pd.DataFrame) -> str:
    digest = hashlib.sha256()
    digest.update(pd.util.hash_pandas_object(frame, index=True).values.tobytes())
    return digest.hexdigest()


def validate_and_clean_frame(
    frame: pd.DataFrame,
    *,
    require_label: bool = True,
    min_rows: int = 20,
) -> tuple[pd.DataFrame, DatasetSummary | None]:
    if not isinstance(frame, pd.DataFrame):
        raise DatasetValidationError("Input must be a table/data frame.")
    if frame.empty:
        raise DatasetValidationError("The dataset is empty.")
    if len(frame.columns) < 2:
        raise DatasetValidationError("The dataset must contain at least two columns.")

    clean = normalize_columns(frame)
    label_column = _first_present(clean.columns, LABEL_ALIASES)
    attack_column = _first_present(clean.columns, ATTACK_ALIASES)

    if require_label and label_column is None and attack_column is None:
        raise DatasetValidationError(
            "Missing target. Add 'label' (0 normal, 1 attack) or 'attack_cat'."
        )
    if not require_label:
        numeric_columns = clean.select_dtypes(include=[np.number]).columns
        clean[numeric_columns] = clean[numeric_columns].replace([np.inf, -np.inf], np.nan)
        return clean, None

    if label_column is None and attack_column is not None:
        label_column = "label"
        clean[label_column] = _binary_target(clean[attack_column])
    elif label_column is not None:
        clean[label_column] = _binary_target(clean[label_column])

    before = len(clean)
    clean = clean.drop_duplicates().reset_index(drop=True)
    duplicates_removed = before - len(clean)
    if len(clean) < min_rows:
        raise DatasetValidationError(
            f"At least {min_rows} usable rows are required; found {len(clean)}."
        )

    numeric = clean.select_dtypes(include=[np.number])
    infinite_count = int(np.isinf(numeric.to_numpy(dtype=float, na_value=np.nan)).sum())
    clean[numeric.columns] = clean[numeric.columns].replace([np.inf, -np.inf], np.nan)
    missing_count = int(clean.isna().sum().sum())

    y = clean[label_column]
    normal_rows = int((y == 0).sum())
    attack_rows = int((y == 1).sum())
    if normal_rows == 0 or attack_rows == 0:
        raise DatasetValidationError(
            "Training requires both normal (0) and attack (1) records."
        )

    if attack_column:
        clean[attack_column] = clean[attack_column].fillna("Unknown").astype(str).str.strip()
        clean.loc[clean[label_column] == 0, attack_column] = "Normal"
        distribution = {
            str(k): int(v)
            for k, v in clean[attack_column].value_counts(dropna=False).to_dict().items()
        }
    else:
        distribution = {"Normal": normal_rows, "Attack": attack_rows}

    summary = DatasetSummary(
        rows=len(clean),
        columns=len(clean.columns),
        duplicate_rows_removed=duplicates_removed,
        missing_values=missing_count,
        infinite_values_replaced=infinite_count,
        label_column=label_column,
        attack_column=attack_column,
        normal_rows=normal_rows,
        attack_rows=attack_rows,
        class_distribution=distribution,
        sha256=_sha256_frame(clean),
    )
    return clean, summary


def load_csv(path: str | Path, *, max_bytes: int | None = None) -> pd.DataFrame:
    csv_path = Path(path).resolve()
    if csv_path.suffix.lower() != ".csv":
        raise DatasetValidationError("Only CSV datasets are supported in version 1.")
    if not csv_path.is_file():
        raise DatasetValidationError(f"Dataset not found: {csv_path.name}")
    if max_bytes is not None and csv_path.stat().st_size > max_bytes:
        raise DatasetValidationError(
            f"Dataset exceeds the configured upload limit ({max_bytes} bytes)."
        )
    try:
        return pd.read_csv(csv_path, low_memory=False)
    except (UnicodeDecodeError, pd.errors.ParserError, ValueError) as exc:
        raise DatasetValidationError(f"Malformed CSV: {exc}") from exc
