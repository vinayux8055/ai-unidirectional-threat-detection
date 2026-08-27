from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    """Load a minimal KEY=VALUE file without adding another dependency."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


PROJECT_ROOT = Path(__file__).resolve().parents[2]
_load_dotenv(PROJECT_ROOT / ".env")


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "ThreatGuard UniFlow AI")
    app_secret: str = os.getenv("APP_SECRET", "development-only-change-me")
    admin_email: str = os.getenv("ADMIN_EMAIL", "admin@threatguard.local")
    admin_password: str = os.getenv("ADMIN_PASSWORD", "ChangeMe123!")
    max_upload_mb: int = int(os.getenv("MAX_UPLOAD_MB", "250"))
    max_training_rows: int = int(os.getenv("MAX_TRAINING_ROWS", "250000"))
    random_state: int = int(os.getenv("RANDOM_STATE", "42"))

    root: Path = PROJECT_ROOT
    data_dir: Path = PROJECT_ROOT / "data"
    uploads_dir: Path = PROJECT_ROOT / "data" / "uploads"
    sample_dir: Path = PROJECT_ROOT / "data" / "sample"
    models_dir: Path = PROJECT_ROOT / "models"
    reports_dir: Path = PROJECT_ROOT / "reports"
    database_path: Path = PROJECT_ROOT / "threatguard.db"

    def ensure_directories(self) -> None:
        for path in (
            self.data_dir,
            self.uploads_dir,
            self.sample_dir,
            self.models_dir,
            self.reports_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_directories()

