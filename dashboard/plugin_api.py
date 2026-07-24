"""Spook Shack dashboard plugin backend."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from spook_shack.intel import (
    cluster_rows,
    correlation_summary,
    ensure_intel_schema,
    ingest_all_sources,
    ingest_source,
    link_rows,
)
from spook_shack.service import (
    connect,
    create_note,
    create_report_draft,
    get_overview,
    get_report_outline,
    list_notes,
    list_report_runs,
    list_runs,
    list_sources,
    queue_ingestion_run,
    set_source_credentials,
    upsert_source,
)

router = APIRouter()

class SourcePayload(BaseModel):
    source_key: str = Field(min_length=2, max_length=120)
    display_name: str = Field(min_length=2, max_length=200)
    source_type: str = Field(min_length=2, max_length=80)
    ingestion_mode: str = Field(default="scheduled poll", min_length=2, max_length=120)
    schedule: str = Field(default="0 * * * *", min_length=1, max_length=120)
    rate_limit_note: str = Field(default="", max_length=1000)
    policy_note: str = Field(default="", max_length=1000)
    credential_hint: str | None = Field(default=None, max_length=120)
    enabled: bool = True
    credentials: dict[str, Any] | str | None = None

class CredentialPayload(BaseModel):
    credentials: dict[str, Any] | str

class NotePayload(BaseModel):
    target_type: str = Field(min_length=2, max_length=120)
    target_id: str = Field(min_length=2, max_length=120)
    verdict: Literal["true_positive", "false_positive", "unknown"]
    note: str = Field(min_length=1, max_length=4000)
    confidence: float | None = Field(default=None, ge=0, le=1)
    tags: list[str] = Field(default_factory=list)
    created_by: str = Field(default="analyst", max_length=120)

class QueuePayload(BaseModel):
    reason: str | None = Field(default=None, max_length=500)
    mode: str = Field(default="queued", max_length=40)
    requested_by: str = Field(default="admin", max_length=120)

class DraftPayload(BaseModel):
    cadence: Literal["weekly", "monthly", "quarterly", "annual"] = "weekly"
    created_by: str = Field(default="analyst", max_length=120)

def _role(request: Request) -> str:
    return (request.headers.get("X-Spook-Shack-Role") or "analyst").strip().lower() or "analyst"

@router.get("/health")
def health() -> dict[str, Any]:
    with connect() as conn:
        return {
            "ok": True,
            "db_path": str(conn.execute("PRAGMA database_list").fetchone()[2]),
            "sources": len(list_sources(conn)),
            "runs": len(list_runs(conn, limit=100)),
            "notes": len(list_notes(conn, limit=100)),
            "reports": len(list_report_runs(conn, limit=100)),
        }

@router.get("/overview")
def overview(request: Request) -> dict[str, Any]:
    with connect() as conn:
        overview = get_overview(conn, role=_role(request))
        overview["correlation"] = correlation_summary(conn)
        return overview

@router.get("/roadmap")
def roadmap() -> dict[str, Any]:
    with connect() as conn:
        return {"roadmap": get_overview(conn).get("roadmap", [])}

@router.get("/sources")
def sources(request: Request) -> dict[str, Any]:
    with connect() as conn:
        return {"role": _role(request), "sources": list_sources(conn)}

@router.post("/sources")
def save_source(request: Request, payload: SourcePayload) -> dict[str, Any]:
    role = _role(request)
    with connect() as conn:
        try:
            source = upsert_source(conn, payload.model_dump(), actor_role=role)
            if payload.credentials is not None:
                set_source_credentials(conn, payload.source_key, payload.credentials, actor_role=role)
                source = list_sources(conn)[0] if source is None else source
            return {"ok": True, "source": source}
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (ValueError, KeyError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.post("/sources/{source_key}/credentials")
def save_credentials(source_key: str, request: Request, payload: CredentialPayload) -> dict[str, Any]:
    role = _role(request)
    with connect() as conn:
        try:
            return set_source_credentials(conn, source_key, payload.credentials, actor_role=role)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

@router.post("/sources/{source_key}/queue")
def queue_source(source_key: str, request: Request, payload: QueuePayload) -> dict[str, Any]:
    role = _role(request)
    with connect() as conn:
        try:
            run = queue_ingestion_run(conn, source_key, actor_role=role, requested_by=payload.requested_by, mode=payload.mode, reason=payload.reason)
            return {"ok": True, "run": run}
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

@router.get("/runs")
def runs(limit: int = 20) -> dict[str, Any]:
    with connect() as conn:
        return {"runs": list_runs(conn, limit=limit)}

@router.get("/notes")
def notes(limit: int = 20) -> dict[str, Any]:
    with connect() as conn:
        return {"notes": list_notes(conn, limit=limit)}

@router.post("/notes")
def add_note(request: Request, payload: NotePayload) -> dict[str, Any]:
    role = _role(request)
    with connect() as conn:
        try:
            return {"ok": True, "note": create_note(conn, payload.model_dump(), actor_role=role)}
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.get("/correlation")
def correlation() -> dict[str, Any]:
    with connect() as conn:
        return {
            "summary": correlation_summary(conn),
            "clusters": cluster_rows(conn, limit=25),
            "links": link_rows(conn, limit=25),
        }

@router.post("/sources/{source_key}/ingest")
def ingest_one(source_key: str, request: Request) -> dict[str, Any]:
    role = _role(request)
    with connect() as conn:
        try:
            return {"ok": True, "result": ingest_source(conn, source_key, actor_role=role)}
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (ValueError, KeyError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.post("/ingest/all")
def ingest_everything(request: Request) -> dict[str, Any]:
    role = _role(request)
    with connect() as conn:
        try:
            return {"ok": True, "results": ingest_all_sources(conn, actor_role=role)}
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.get("/reports")
def reports(limit: int = 10) -> dict[str, Any]:
    with connect() as conn:
        return {"reports": list_report_runs(conn, limit=limit)}

@router.get("/reports/template")
def report_template() -> dict[str, Any]:
    return {"outline": get_report_outline()}

@router.post("/reports/draft")
def draft_report(request: Request, payload: DraftPayload) -> dict[str, Any]:
    role = _role(request)
    with connect() as conn:
        try:
            return {"ok": True, "report": create_report_draft(conn, payload.cadence, actor_role=role, created_by=payload.created_by)}
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
