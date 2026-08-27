from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Annotated, Any

import pandas as pd
from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from .auth import create_access_token, decode_access_token
from .config import settings
from .data import DatasetValidationError
from .models import SUPPORTED_ALGORITHMS
from .service import service


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="Defensive AI-assisted detection of threats from unidirectional flow metadata.",
)
bearer = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=10, max_length=200)


class TrainRequest(BaseModel):
    dataset_path: str
    profile: str = "unidirectional"
    algorithms: list[str] = list(SUPPORTED_ALGORITHMS)


class PredictRequest(BaseModel):
    flow: dict[str, Any]
    persist: bool = True


def current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> dict[str, Any]:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Login required.")
    try:
        return decode_access_token(credentials.credentials, settings.app_secret)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc


def require_researcher(user: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
    if user["role"] not in {"administrator", "researcher"}:
        raise HTTPException(status_code=403, detail="Researcher permission required.")
    return user


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy", "service": settings.app_name}


@app.post("/auth/login")
def login(request: LoginRequest) -> dict[str, Any]:
    user = service.database.authenticate(request.email, request.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    token = create_access_token(user["email"], user["role"], settings.app_secret)
    service.database.audit(user["email"], "LOGIN", {"role": user["role"]})
    return {"access_token": token, "token_type": "bearer", "user": user}


@app.post("/datasets/upload")
async def upload_dataset(
    file: Annotated[UploadFile, File(...)],
    user: Annotated[dict[str, Any], Depends(require_researcher)],
) -> dict[str, Any]:
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are accepted.")
    total = 0
    try:
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as temporary:
            temp_path = Path(temporary.name)
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > settings.max_upload_mb * 1024 * 1024:
                    raise HTTPException(status_code=413, detail="Upload is too large.")
                temporary.write(chunk)
        stored = service.store_upload(temp_path, file.filename)
        result = service.validate_dataset(stored)
        service.database.audit(user["sub"], "DATASET_UPLOADED", {"path": str(stored)})
        return {"dataset_path": str(stored), **result}
    except DatasetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        if "temp_path" in locals():
            temp_path.unlink(missing_ok=True)


@app.post("/models/train")
def train_model(
    request: TrainRequest,
    user: Annotated[dict[str, Any], Depends(require_researcher)],
) -> dict[str, Any]:
    path = Path(request.dataset_path).resolve()
    allowed_roots = (settings.uploads_dir.resolve(), settings.sample_dir.resolve())
    if not any(root in path.parents for root in allowed_roots):
        raise HTTPException(status_code=400, detail="Dataset path is outside approved directories.")
    try:
        return service.train(
            path,
            profile_name=request.profile,
            algorithms=request.algorithms,
            actor=user["sub"],
        )
    except (DatasetValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/models")
def models(_: Annotated[dict[str, Any], Depends(current_user)]) -> list[dict[str, Any]]:
    return service.database.list_models()


@app.get("/models/performance")
def model_performance(_: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
    try:
        return service.model_performance()
    except RuntimeError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/predict")
def predict(
    request: PredictRequest,
    _: Annotated[dict[str, Any], Depends(current_user)],
) -> dict[str, Any]:
    try:
        return service.predict_one(request.flow, persist=request.persist)
    except (DatasetValidationError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/predict/batch")
def predict_batch(
    flows: list[dict[str, Any]],
    _: Annotated[dict[str, Any], Depends(current_user)],
) -> list[dict[str, Any]]:
    if not flows or len(flows) > 10_000:
        raise HTTPException(status_code=400, detail="Batch size must be from 1 to 10,000.")
    try:
        return service.predict_frame(pd.DataFrame(flows), persist=True)
    except (DatasetValidationError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/alerts")
def alerts(
    _: Annotated[dict[str, Any], Depends(current_user)],
    risk_level: str | None = None,
    attack_type: str | None = None,
    protocol: str | None = None,
    source: str | None = None,
    destination: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[dict[str, Any]]:
    return service.database.list_alerts(
        risk_level=risk_level,
        attack_type=attack_type,
        protocol=protocol,
        source=source,
        destination=destination,
        date_from=date_from,
        date_to=date_to,
        limit=limit,
    )


@app.get("/alerts/{alert_id}")
def alert_by_id(
    alert_id: int,
    _: Annotated[dict[str, Any], Depends(current_user)],
) -> dict[str, Any]:
    matches = [row for row in service.database.list_alerts(limit=1000) if row["alert_id"] == alert_id]
    if not matches:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return matches[0]


@app.get("/analytics")
def analytics(_: Annotated[dict[str, Any], Depends(current_user)]) -> dict[str, Any]:
    return service.database.analytics()
