from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from .auth import hash_password, verify_password


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('administrator','security_analyst','researcher')),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS datasets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    row_count INTEGER NOT NULL,
    column_count INTEGER NOT NULL,
    summary_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version TEXT NOT NULL UNIQUE,
    profile TEXT NOT NULL,
    dataset_sha256 TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    feature_schema_json TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT,
    destination_ip TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT,
    features_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id INTEGER NOT NULL REFERENCES network_flows(id),
    model_version TEXT NOT NULL,
    prediction TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    probability REAL NOT NULL CHECK(probability BETWEEN 0 AND 1),
    risk_score INTEGER NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prediction_id INTEGER NOT NULL REFERENCES predictions(id),
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','INVESTIGATING','CLOSED','FALSE_POSITIVE')),
    analyst_note TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_predictions_created ON predictions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_predictions_risk ON predictions(risk_level);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_models_active ON models(active);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    def ensure_admin(self, email: str, password: str) -> None:
        with self.connect() as connection:
            exists = connection.execute(
                "SELECT 1 FROM users WHERE email = ?", (email,)
            ).fetchone()
            if not exists:
                connection.execute(
                    "INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                    ("System Administrator", email, hash_password(password), "administrator", utc_now()),
                )

    def authenticate(self, email: str, password: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id,name,email,password_hash,role FROM users WHERE email=? AND active=1",
                (email.strip().lower(),),
            ).fetchone()
        if row and verify_password(password, row["password_hash"]):
            return {k: row[k] for k in ("id", "name", "email", "role")}
        return None

    def add_dataset(self, name: str, path: str, summary: dict[str, Any]) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """INSERT INTO datasets(name,path,sha256,row_count,column_count,summary_json,created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (
                    name,
                    path,
                    summary["sha256"],
                    summary["rows"],
                    summary["columns"],
                    json.dumps(summary),
                    utc_now(),
                ),
            )
            return int(cursor.lastrowid)

    def add_model(self, metadata: dict[str, Any], artifact_path: str, *, activate: bool) -> int:
        with self.connect() as connection:
            if activate:
                connection.execute("UPDATE models SET active=0")
            cursor = connection.execute(
                """INSERT INTO models(name,version,profile,dataset_sha256,artifact_path,
                                      metrics_json,feature_schema_json,active,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    metadata["model_name"],
                    metadata["version"],
                    metadata["profile"]["name"],
                    metadata["dataset_sha256"],
                    artifact_path,
                    json.dumps(metadata["metrics"]),
                    json.dumps(metadata["profile"]),
                    int(activate),
                    metadata["created_at"],
                ),
            )
            return int(cursor.lastrowid)

    def get_active_model(self) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM models WHERE active=1 ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def list_models(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM models ORDER BY id DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def record_prediction(self, flow: dict[str, Any], result: dict[str, Any]) -> dict[str, int | None]:
        with self.connect() as connection:
            flow_cursor = connection.execute(
                """INSERT INTO network_flows(source_ip,destination_ip,source_port,
                   destination_port,protocol,features_json,created_at) VALUES(?,?,?,?,?,?,?)""",
                (
                    flow.get("src_ip") or flow.get("source_ip"),
                    flow.get("dst_ip") or flow.get("destination_ip"),
                    _safe_int(flow.get("src_port") or flow.get("source_port")),
                    _safe_int(flow.get("dst_port") or flow.get("destination_port")),
                    str(flow.get("proto") or flow.get("protocol") or "unknown"),
                    json.dumps(flow, default=str),
                    utc_now(),
                ),
            )
            prediction_cursor = connection.execute(
                """INSERT INTO predictions(flow_id,model_version,prediction,attack_type,
                   probability,risk_score,risk_level,latency_ms,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    flow_cursor.lastrowid,
                    result["model_version"],
                    result["prediction"],
                    result["attack_type"],
                    result["threat_probability"],
                    result["risk_score"],
                    result["risk_level"],
                    result["latency_ms"],
                    utc_now(),
                ),
            )
            alert_id: int | None = None
            if result["prediction"] == "ATTACK":
                alert_cursor = connection.execute(
                    "INSERT INTO alerts(prediction_id,created_at) VALUES(?,?)",
                    (prediction_cursor.lastrowid, utc_now()),
                )
                alert_id = int(alert_cursor.lastrowid)
            return {
                "flow_id": int(flow_cursor.lastrowid),
                "prediction_id": int(prediction_cursor.lastrowid),
                "alert_id": alert_id,
            }

    def list_alerts(
        self,
        *,
        risk_level: str | None = None,
        attack_type: str | None = None,
        protocol: str | None = None,
        source: str | None = None,
        destination: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses = ["1=1"]
        params: list[Any] = []
        if risk_level:
            clauses.append("p.risk_level=?")
            params.append(risk_level.upper())
        if attack_type:
            clauses.append("p.attack_type=?")
            params.append(attack_type)
        if protocol:
            clauses.append("LOWER(f.protocol)=LOWER(?)")
            params.append(protocol)
        if source:
            clauses.append("f.source_ip LIKE ?")
            params.append(f"%{source}%")
        if destination:
            clauses.append("f.destination_ip LIKE ?")
            params.append(f"%{destination}%")
        if date_from:
            clauses.append("a.created_at>=?")
            params.append(date_from)
        if date_to:
            clauses.append("a.created_at<=?")
            params.append(date_to)
        params.append(max(1, min(int(limit), 1000)))
        query = f"""
            SELECT a.id AS alert_id,a.status,a.analyst_note,a.created_at,
                   p.prediction,p.attack_type,p.probability,p.risk_score,p.risk_level,
                   p.model_version,p.latency_ms,
                   f.source_ip,f.destination_ip,f.source_port,f.destination_port,f.protocol
            FROM alerts a
            JOIN predictions p ON p.id=a.prediction_id
            JOIN network_flows f ON f.id=p.flow_id
            WHERE {' AND '.join(clauses)}
            ORDER BY a.id DESC LIMIT ?
        """
        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def analytics(self) -> dict[str, Any]:
        with self.connect() as connection:
            totals = connection.execute(
                """SELECT COUNT(*) total,
                   SUM(CASE WHEN prediction='NORMAL' THEN 1 ELSE 0 END) normal,
                   SUM(CASE WHEN prediction='ATTACK' THEN 1 ELSE 0 END) attacks,
                   SUM(CASE WHEN risk_level='CRITICAL' THEN 1 ELSE 0 END) critical
                   FROM predictions"""
            ).fetchone()
            risk = connection.execute(
                "SELECT risk_level label,COUNT(*) count FROM predictions GROUP BY risk_level"
            ).fetchall()
            attacks = connection.execute(
                """SELECT attack_type label,COUNT(*) count FROM predictions
                   WHERE prediction='ATTACK' GROUP BY attack_type ORDER BY count DESC"""
            ).fetchall()
            trend = connection.execute(
                """SELECT substr(created_at,1,10) day,COUNT(*) count FROM predictions
                   WHERE prediction='ATTACK' GROUP BY day ORDER BY day"""
            ).fetchall()
        return {
            "totals": {k: int(totals[k] or 0) for k in totals.keys()},
            "risk_distribution": [dict(row) for row in risk],
            "attack_distribution": [dict(row) for row in attacks],
            "threat_trend": [dict(row) for row in trend],
        }

    def audit(self, actor: str, action: str, details: dict[str, Any]) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO audit_logs(actor,action,details_json,created_at) VALUES(?,?,?,?)",
                (actor, action, json.dumps(details, default=str), utc_now()),
            )


def _safe_int(value: Any) -> int | None:
    try:
        return int(float(value)) if value is not None else None
    except (TypeError, ValueError):
        return None
