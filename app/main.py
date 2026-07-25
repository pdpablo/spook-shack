from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from urllib.parse import urljoin, urlsplit

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select, text
from starlette.middleware.sessions import SessionMiddleware

from .db import Base, SessionLocal, engine
from .models import AnalystNote, ForecastItem, FutureTechBrief, IntelligenceItem, IngestionRun, ReportRun, Source, User
from .schemas import ForecastImportRequest, ItemCreate, LoginRequest, NoteCreate, SourceCreate, SourceDiscoveryRequest, UserRoleUpdate, VerdictUpdate
from spook_shack.service import create_report_draft, get_report_outline, get_report_run, list_report_runs
from spook_shack.intel import correlation_summary, ingest_source
from .security import DefaultCredentials, hash_password, new_token, verify_password

BASE_DIR = Path(os.getenv("SPOOK_SHACK_APP_ROOT", Path.cwd())).resolve()
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))
STATIC_DIR = BASE_DIR / "static"
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "dev-only-change-me")
DEFAULT_ACCOUNTS = DefaultCredentials()

app = FastAPI(title="Spook Shack", version="0.1.0")
app.add_middleware(SessionMiddleware, secret_key=APP_SECRET_KEY, session_cookie="spookshack_session")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DbSession = Annotated[object, Depends(get_db)]


NAV_LINKS = [
    {"href": "/", "label": "Overview"},
    {"href": "/sources", "label": "Sources"},
    {"href": "/discover", "label": "Discover"},
    {"href": "/ingestions", "label": "Ingestions"},
    {"href": "/notes", "label": "Notes"},
    {"href": "/correlation", "label": "Correlation"},
    {"href": "/reports", "label": "Reports"},
    {"href": "/forecast", "label": "Forecast"},
    {"href": "/governance", "label": "Governance"},
]


def migrate_schema(db) -> None:
    columns = {row[1] for row in db.execute(text("PRAGMA table_info(sources)")).all()}
    if "feed_url" not in columns:
        db.execute(text("ALTER TABLE sources ADD COLUMN feed_url VARCHAR(512)"))
    if "crawl_delay_seconds" not in columns:
        db.execute(text("ALTER TABLE sources ADD COLUMN crawl_delay_seconds INTEGER NOT NULL DEFAULT 0"))
    brief_columns = {row[1] for row in db.execute(text("PRAGMA table_info(future_briefs)")).all()}
    if brief_columns and "existing_technology" not in brief_columns:
        db.execute(text("ALTER TABLE future_briefs ADD COLUMN existing_technology VARCHAR(256) NOT NULL DEFAULT ''"))
    if brief_columns and "raw_report_json" not in brief_columns:
        db.execute(text("ALTER TABLE future_briefs ADD COLUMN raw_report_json TEXT NOT NULL DEFAULT '{}'"))
    run_columns = {row[1] for row in db.execute(text("PRAGMA table_info(ingestion_runs)")).all()}
    if run_columns and "mode" not in run_columns:
        db.execute(text("ALTER TABLE ingestion_runs ADD COLUMN mode VARCHAR(32) NOT NULL DEFAULT 'manual'"))
    if run_columns and "requested_by" not in run_columns:
        db.execute(text("ALTER TABLE ingestion_runs ADD COLUMN requested_by VARCHAR(64) NOT NULL DEFAULT 'admin'"))


def seed_default_data(db):
    migrate_schema(db)
    if not db.execute(select(User).limit(1)).scalar_one_or_none():
        db.add(User(username=DEFAULT_ACCOUNTS.admin_username, password_hash=hash_password(DEFAULT_ACCOUNTS.admin_password), role="admin"))
        db.add(User(username=DEFAULT_ACCOUNTS.analyst_username, password_hash=hash_password(DEFAULT_ACCOUNTS.analyst_password), role="analyst"))
        db.commit()

    if not db.execute(select(Source).limit(1)).scalar_one_or_none():
        sources = [
            Source(name="ransomware.live", source_type="feed", url="https://ransomware.live", feed_url="https://ransomware.live/rss.xml", access_method="api", rate_limit_per_minute=30, crawl_delay_seconds=90, schedule="*/30 * * * *", policy_notes="Use public endpoints and obey rate limits."),
            Source(name="Telegram Leaks", source_type="messaging", url="https://telegram.org", access_method="approved_client", rate_limit_per_minute=20, crawl_delay_seconds=120, schedule="0 * * * *", policy_notes="Only ingest channels the operator is authorized to access."),
            Source(name="TweetFeed", source_type="social", url="https://x.com", feed_url="https://tweetfeed.live/rss.xml", access_method="api", rate_limit_per_minute=15, crawl_delay_seconds=60, schedule="*/20 * * * *", policy_notes="Use official or permitted access methods only."),
            Source(name="PhishHunt", source_type="feed", url="https://phishunt.io", feed_url="https://phishunt.io/rss", access_method="api", rate_limit_per_minute=30, crawl_delay_seconds=90, schedule="*/15 * * * *", policy_notes="Respect feed terms and documented limits."),
            Source(name="HaveIBeenPwned", source_type="api", url="https://haveibeenpwned.com", access_method="api", rate_limit_per_minute=4, crawl_delay_seconds=0, schedule="0 */6 * * *", policy_notes="Use the official API and its rate limits."),
        ]
        db.add_all(sources)
        db.commit()

    if not db.execute(select(ForecastItem).limit(1)).scalar_one_or_none():
        db.add_all([
            ForecastItem(
                title="Agentic desktop workflows",
                technology_class="automation",
                related_technology="RPA and browser automation",
                attack_surface="Token theft, prompt injection, plugin abuse, and insecure local automation.",
                threat_use="Threat actors could use agentic workflows to accelerate phishing, persistence, and data theft.",
                confidence=72,
            ),
            ForecastItem(
                title="Private on-device LLM orchestration",
                technology_class="ai-inference",
                related_technology="local ML runtimes and device management tools",
                attack_surface="Model supply chain compromise, unsafe plugin loading, and local secret exposure.",
                threat_use="Adversaries may target orchestration layers to extract prompts, secrets, and workspace data.",
                confidence=68,
            ),
        ])
        db.commit()

    if not db.execute(select(FutureTechBrief).limit(1)).scalar_one_or_none():
        db.add(
            FutureTechBrief(
                title="Post-quantum migration attack-surface forecast",
                classification="emerging-technology",
                related_technology="Hybrid X25519 / ML-KEM deployments",
                existing_technology="PKI, TLS termination, and software supply-chain tooling",
                attack_vectors_json=json.dumps([
                    "Downgrade attacks on hybrid negotiation",
                    "Implementation confusion during gradual rollout",
                    "Supply-chain replacement of crypto libraries",
                ]),
                threat_actor_use_json=json.dumps([
                    "Phish operations that force fallback behavior",
                    "Targeting long-lived secrets during transition windows",
                ]),
                source_notes_json=json.dumps([
                    "Track new PQ migration papers and implementation notes.",
                    "Annotate Hermes-agent reports with the nearest existing stack.",
                ]),
                summary="Prototype forecast to demonstrate the future-tech dashboard and the Hermes-agent report import flow.",
                raw_report_json=json.dumps({"source": "seed", "style": "seed"}),
                confidence=72,
            )
        )
        db.commit()

    if not db.execute(select(IntelligenceItem).limit(1)).scalar_one_or_none():
        seed_items(db)


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_default_data(db)


def seed_items(db) -> None:
    sources = {source.name: source for source in db.execute(select(Source)).scalars().all()}
    seeds = [
        ("ransomware.live", "ALPHV leak post", "Leak activity suggests renewed pressure on victim infrastructure.", "domain", "example-victim[.]com", 84, "unknown"),
        ("Telegram Leaks", "Credential dump mention", "A channel post references fresh credential bundles and access resale.", "email", "admin@example.com", 78, "unknown"),
        ("TweetFeed", "Threat actor chatter", "Public chatter mentions lateral movement tooling and cloud abuse.", "keyword", "cloud abuse", 62, "unknown"),
        ("PhishHunt", "New phishing lure", "A lure impersonates software updates and uses credential harvesting.", "url", "hxxps://update-example[.]com", 91, "true_positive"),
        ("HaveIBeenPwned", "Breach exposure notice", "Breach exposure confirmed for a monitored address set.", "email", "user@example.com", 88, "false_positive"),
    ]
    for source_name, title, summary, observable_type, observable_value, confidence, verdict in seeds:
        source = sources.get(source_name)
        if not source:
            continue
        db.add(
            IntelligenceItem(
                source_id=source.id,
                title=title,
                summary=summary,
                observable_type=observable_type,
                observable_value=observable_value,
                confidence=confidence,
                verdict=verdict,
                raw_excerpt=summary,
            )
        )
    db.commit()


def current_user(request: Request, db):
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.get(User, user_id)


def require_user(request: Request, db):
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user


def require_admin(user: User) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "spook-shack"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return TEMPLATES.TemplateResponse(
        request,
        "login.html",
        {
            "admin_username": DEFAULT_ACCOUNTS.admin_username,
            "analyst_username": DEFAULT_ACCOUNTS.analyst_username,
        },
    )


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), db=Depends(get_db)):
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if not user or not verify_password(password, user.password_hash):
        return TEMPLATES.TemplateResponse(
            request,
            "login.html",
            {
                "error": "Invalid username or password.",
                "admin_username": DEFAULT_ACCOUNTS.admin_username,
                "analyst_username": DEFAULT_ACCOUNTS.analyst_username,
            },
            status_code=401,
        )
    request.session["user_id"] = user.id
    request.session["username"] = user.username
    request.session["role"] = user.role
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return response


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    q: str | None = None,
    verdict: str | None = None,
    source_id: int | None = None,
    sort: str = "newest",
    db=Depends(get_db),
):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    sources = db.execute(select(Source).order_by(Source.name)).scalars().all()
    source_stats = db.execute(
        select(Source, func.count(IntelligenceItem.id))
        .outerjoin(IntelligenceItem, IntelligenceItem.source_id == Source.id)
        .group_by(Source.id)
        .order_by(Source.name)
    ).all()

    item_stmt = select(IntelligenceItem, Source.name).join(Source, Source.id == IntelligenceItem.source_id)
    search_term = (q or "").strip()
    if search_term:
        pattern = f"%{search_term}%"
        item_stmt = item_stmt.where(
            or_(
                IntelligenceItem.title.ilike(pattern),
                IntelligenceItem.summary.ilike(pattern),
                IntelligenceItem.observable_value.ilike(pattern),
                Source.name.ilike(pattern),
            )
        )
    if verdict in {"unknown", "true_positive", "false_positive"}:
        item_stmt = item_stmt.where(IntelligenceItem.verdict == verdict)
    if source_id is not None:
        item_stmt = item_stmt.where(IntelligenceItem.source_id == source_id)

    sort_options = {
        "newest": IntelligenceItem.created_at.desc(),
        "oldest": IntelligenceItem.created_at.asc(),
        "highest_confidence": IntelligenceItem.confidence.desc(),
        "lowest_confidence": IntelligenceItem.confidence.asc(),
    }
    item_stmt = item_stmt.order_by(sort_options.get(sort, IntelligenceItem.created_at.desc()))

    total_items = db.execute(select(func.count(IntelligenceItem.id))).scalar_one()
    filtered_item_count = db.execute(select(func.count()).select_from(item_stmt.subquery())).scalar_one()
    items = db.execute(item_stmt.limit(20)).all()
    forecasts = db.execute(select(ForecastItem).order_by(ForecastItem.created_at.desc())).scalars().all()
    summary = dashboard_summary_data(db)
    recent_ingestions = db.execute(
        select(IngestionRun, Source.name)
        .join(Source, Source.id == IngestionRun.source_id)
        .order_by(IngestionRun.created_at.desc())
        .limit(5)
    ).all()
    queue_counts = dict(
        db.execute(
            select(IngestionRun.status, func.count(IngestionRun.id))
            .group_by(IngestionRun.status)
        ).all()
    )

    rendered_items = []
    visible_confidence_total = 0
    for item, source_name in items:
        note_rows = db.execute(
            select(AnalystNote, User.username)
            .join(User, User.id == AnalystNote.author_id)
            .where(AnalystNote.item_id == item.id)
            .order_by(AnalystNote.created_at.desc())
        ).all()
        rendered_items.append((item, source_name, note_rows))
        visible_confidence_total += item.confidence

    dashboard_filters = {
        "q": search_term,
        "verdict": verdict if verdict in {"unknown", "true_positive", "false_positive"} else "",
        "source_id": source_id or "",
        "sort": sort if sort in sort_options else "newest",
    }
    visible_item_count = len(rendered_items)
    visible_average_confidence = round(visible_confidence_total / visible_item_count) if visible_item_count else 0

    return TEMPLATES.TemplateResponse(
        request,
        "overview.html",
        _page_context(
            request,
            title="Spook Shack · Overview",
            active_page="overview",
            user=user,
            sources=sources,
            source_stats=source_stats,
            items=rendered_items,
            forecasts=forecasts,
            summary=summary,
            queue_counts=queue_counts,
            recent_ingestions=recent_ingestions,
            total_item_count=total_items,
            filtered_item_count=filtered_item_count,
            visible_item_count=visible_item_count,
            visible_average_confidence=visible_average_confidence,
            filters=dashboard_filters,
        ),
    )


@app.get("/api/me")
def api_me(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"username": user.username, "role": user.role}


@app.get("/api/dashboard/summary")
def api_summary(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return dashboard_summary_data(db)


@app.get("/api/sources")
def api_sources(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return [
        {
            "id": source.id,
            "name": source.name,
            "source_type": source.source_type,
            "url": source.url,
            "feed_url": source.feed_url,
            "access_method": source.access_method,
            "rate_limit_per_minute": source.rate_limit_per_minute,
            "crawl_delay_seconds": source.crawl_delay_seconds,
            "schedule": source.schedule,
            "enabled": source.enabled,
            "last_sync_at": source.last_sync_at,
        }
        for source in db.execute(select(Source).order_by(Source.name)).scalars().all()
    ]


@app.post("/api/sources")
def api_create_source(request: Request, payload: SourceCreate, db=Depends(get_db)):
    user = require_user(request, db)
    require_admin(user)
    source = Source(
        name=payload.name,
        source_type=payload.source_type,
        url=payload.url,
        feed_url=payload.feed_url,
        access_method=payload.access_method,
        rate_limit_per_minute=payload.rate_limit_per_minute,
        crawl_delay_seconds=payload.crawl_delay_seconds,
        schedule=payload.schedule,
        policy_notes=payload.policy_notes,
        enabled=payload.enabled,
    )
    db.add(source)
    db.commit()
    return {"id": source.id, "name": source.name}


@app.post("/sources")
def create_source_form(
    request: Request,
    name: str = Form(...),
    source_type: str = Form("feed"),
    url: str | None = Form(None),
    feed_url: str | None = Form(None),
    access_method: str = Form("api"),
    rate_limit_per_minute: int = Form(60),
    crawl_delay_seconds: int = Form(0),
    schedule: str = Form("*/30 * * * *"),
    policy_notes: str = Form("Comply with source AUP and rate limits."),
    enabled: bool = Form(True),
    db=Depends(get_db),
):
    user = require_user(request, db)
    require_admin(user)
    source = Source(
        name=name,
        source_type=source_type,
        url=url,
        feed_url=feed_url,
        access_method=access_method,
        rate_limit_per_minute=rate_limit_per_minute,
        crawl_delay_seconds=crawl_delay_seconds,
        schedule=schedule,
        policy_notes=policy_notes,
        enabled=enabled,
    )
    db.add(source)
    db.commit()
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/api/items")
def api_create_item(request: Request, payload: ItemCreate, db=Depends(get_db)):
    user = require_user(request, db)
    require_admin(user)
    source = db.get(Source, payload.source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    item = IntelligenceItem(
        source_id=payload.source_id,
        title=payload.title,
        summary=payload.summary,
        observable_type=payload.observable_type,
        observable_value=payload.observable_value,
        confidence=payload.confidence,
        raw_excerpt=payload.raw_excerpt or payload.summary,
    )
    db.add(item)
    db.commit()
    return {"id": item.id, "title": item.title}


@app.post("/api/items/{item_id}/notes")
def api_add_note(request: Request, item_id: int, payload: NoteCreate, db=Depends(get_db)):
    user = require_user(request, db)
    item = db.get(IntelligenceItem, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    note = AnalystNote(item_id=item.id, author_id=user.id, note=payload.note)
    db.add(note)
    db.commit()
    return {"id": note.id, "item_id": item.id}


@app.post("/items/{item_id}/notes")
def add_note_form(
    request: Request,
    item_id: int,
    note: str = Form(...),
    db=Depends(get_db),
):
    user = require_user(request, db)
    item = db.get(IntelligenceItem, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    db.add(AnalystNote(item_id=item.id, author_id=user.id, note=note))
    db.commit()
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/api/items/{item_id}/verdict")
def api_update_verdict(request: Request, item_id: int, payload: VerdictUpdate, db=Depends(get_db)):
    user = require_user(request, db)
    require_admin(user)
    item = db.get(IntelligenceItem, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    item.verdict = payload.verdict
    db.add(item)
    db.commit()
    return {"id": item.id, "verdict": item.verdict}


@app.post("/items/{item_id}/verdict")
def update_verdict_form(
    request: Request,
    item_id: int,
    verdict: str = Form(...),
    db=Depends(get_db),
):
    user = require_user(request, db)
    require_admin(user)
    item = db.get(IntelligenceItem, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    item.verdict = verdict
    db.add(item)
    db.commit()
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/items/{item_id}", response_class=HTMLResponse)
def item_detail_page(request: Request, item_id: int, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    item_row = db.execute(
        select(IntelligenceItem, Source.name)
        .join(Source, Source.id == IntelligenceItem.source_id)
        .where(IntelligenceItem.id == item_id)
    ).first()
    if not item_row:
        raise HTTPException(status_code=404, detail="Item not found")
    item, source_name = item_row
    notes = db.execute(
        select(AnalystNote, User.username)
        .join(User, User.id == AnalystNote.author_id)
        .where(AnalystNote.item_id == item_id)
        .order_by(AnalystNote.created_at.desc())
    ).all()
    related_items = db.execute(
        select(IntelligenceItem, Source.name)
        .join(Source, Source.id == IntelligenceItem.source_id)
        .where(IntelligenceItem.source_id == item.source_id, IntelligenceItem.id != item.id)
        .order_by(IntelligenceItem.created_at.desc())
        .limit(8)
    ).all()
    return TEMPLATES.TemplateResponse(
        request,
        "item_detail.html",
        _page_context(
            request,
            title=f"{item.title} · Spook Shack",
            active_page="correlation",
            user=user,
            item=item,
            source_name=source_name,
            notes=notes,
            related_items=related_items,
        ),
    )


@app.post("/api/bootstrap")
def api_bootstrap(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    seed_default_data(db)
    return {"ok": True}


@app.get("/sources", response_class=HTMLResponse)
def sources_page(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    sources = db.execute(select(Source).order_by(Source.name)).scalars().all()
    runs = db.execute(
        select(AnalystNote, IntelligenceItem, Source, User.username)
        .join(IntelligenceItem, IntelligenceItem.id == AnalystNote.item_id)
        .join(Source, Source.id == IntelligenceItem.source_id)
        .join(User, User.id == AnalystNote.author_id)
        .order_by(AnalystNote.created_at.desc())
    ).all()
    return TEMPLATES.TemplateResponse(
        request,
        "sources.html",
        _page_context(
            request,
            title="Sources · Spook Shack",
            active_page="sources",
            user=user,
            sources=sources,
            recent_notes=runs[:10],
            source_discovery=None,
        ),
    )


@app.get("/sources/new", response_class=HTMLResponse)
def sources_new_page(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    return TEMPLATES.TemplateResponse(
        request,
        "sources_new.html",
        _page_context(
            request,
            title="Add Source · Spook Shack",
            active_page="sources",
            user=user,
        ),
    )


@app.post("/sources/discover")
def discover_sources_form(request: Request, url: str = Form(...), db=Depends(get_db)):
    user = require_user(request, db)
    if user.role not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Not allowed")
    discovery = discover_source_candidates(url)
    sources = db.execute(select(Source).order_by(Source.name)).scalars().all()
    return TEMPLATES.TemplateResponse(
        request,
        "sources.html",
        _page_context(
            request,
            title="Sources · Spook Shack",
            active_page="sources",
            user=user,
            sources=sources,
            recent_notes=[],
            source_discovery=discovery,
        ),
    )


@app.get("/discover", response_class=HTMLResponse)
def discover_page(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return TEMPLATES.TemplateResponse(
        request,
        "discover.html",
        _page_context(
            request,
            title="Discover · Spook Shack",
            active_page="discover",
            user=user,
            discovery=None,
        ),
    )


@app.post("/discover")
def discover_page_submit(request: Request, url: str = Form(...), db=Depends(get_db)):
    user = require_user(request, db)
    if user.role not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Not allowed")
    discovery = discover_source_candidates(url)
    return TEMPLATES.TemplateResponse(
        request,
        "discover.html",
        _page_context(
            request,
            title="Discover · Spook Shack",
            active_page="discover",
            user=user,
            discovery=discovery,
        ),
    )


@app.post("/sources/{source_id}/ingest")
def ingest_source_route(request: Request, source_id: int, db=Depends(get_db)):
    user = require_user(request, db)
    require_admin(user)
    source = db.get(Source, source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    result = ingest_source(db, source.name, actor_role=user.role)
    return RedirectResponse(url=f"/sources?ingested={result['run_id']}", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/sources/{source_id}/ingest", response_class=HTMLResponse)
def source_ingest_page(request: Request, source_id: int, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    source = db.get(Source, source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    return TEMPLATES.TemplateResponse(
        request,
        "source_ingest.html",
        _page_context(
            request,
            title=f"Ingest {source.name} · Spook Shack",
            active_page="sources",
            user=user,
            source=source,
        ),
    )


@app.get("/sources/{source_id}", response_class=HTMLResponse)
def source_detail_page(request: Request, source_id: int, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    source = db.get(Source, source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    runs = db.execute(
        select(IngestionRun)
        .where(IngestionRun.source_id == source.id)
        .order_by(IngestionRun.created_at.desc())
        .limit(10)
    ).scalars().all()
    items = db.execute(
        select(IntelligenceItem)
        .where(IntelligenceItem.source_id == source.id)
        .order_by(IntelligenceItem.created_at.desc())
        .limit(10)
    ).scalars().all()
    notes = db.execute(
        select(AnalystNote, User.username, IntelligenceItem.title)
        .join(IntelligenceItem, IntelligenceItem.id == AnalystNote.item_id)
        .join(User, User.id == AnalystNote.author_id)
        .where(IntelligenceItem.source_id == source.id)
        .order_by(AnalystNote.created_at.desc())
        .limit(10)
    ).all()
    return TEMPLATES.TemplateResponse(
        request,
        "source_detail.html",
        _page_context(
            request,
            title=f"{source.name} · Spook Shack",
            active_page="sources",
            user=user,
            source=source,
            runs=runs,
            items=items,
            notes=notes,
        ),
    )


@app.get("/ingestions", response_class=HTMLResponse)
def ingestions_page(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    runs = db.execute(select(IngestionRun, Source.name).join(Source, Source.id == IngestionRun.source_id).order_by(IngestionRun.created_at.desc())).all()
    sources = db.execute(select(Source).order_by(Source.name)).scalars().all()
    return TEMPLATES.TemplateResponse(
        request,
        "ingestions.html",
        _page_context(
            request,
            title="Ingestions · Spook Shack",
            active_page="ingestions",
            user=user,
            runs=runs,
            sources=sources,
        ),
    )


@app.get("/ingestions/new", response_class=HTMLResponse)
def ingestions_new_page(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    sources = db.execute(select(Source).order_by(Source.name)).scalars().all()
    return TEMPLATES.TemplateResponse(
        request,
        "ingestions_new.html",
        _page_context(
            request,
            title="Queue Ingest · Spook Shack",
            active_page="ingestions",
            user=user,
            sources=sources,
        ),
    )


@app.post("/ingestions/queue")
def queue_ingestion(request: Request, source_id: int = Form(...), reason: str = Form(""), db=Depends(get_db)):
    user = require_user(request, db)
    require_admin(user)
    source = db.get(Source, source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Source not found")
    run = IngestionRun(source_id=source.id, status="queued", mode="manual", reason=reason or None, requested_by=user.username)
    db.add(run)
    db.commit()
    return RedirectResponse(url="/ingestions", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/notes", response_class=HTMLResponse)
def notes_page(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    notes = db.execute(
        select(AnalystNote, IntelligenceItem.title, Source.name, User.username)
        .join(IntelligenceItem, IntelligenceItem.id == AnalystNote.item_id)
        .join(Source, Source.id == IntelligenceItem.source_id)
        .join(User, User.id == AnalystNote.author_id)
        .order_by(AnalystNote.created_at.desc())
    ).all()
    recent_items = db.execute(
        select(IntelligenceItem, Source.name)
        .join(Source, Source.id == IntelligenceItem.source_id)
        .order_by(IntelligenceItem.created_at.desc())
        .limit(8)
    ).all()
    return TEMPLATES.TemplateResponse(
        request,
        "notes.html",
        _page_context(
            request,
            title="Notes · Spook Shack",
            active_page="notes",
            user=user,
            notes=notes,
            recent_items=recent_items,
        ),
    )


@app.get("/correlation", response_class=HTMLResponse)
def correlation_page(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    items = db.execute(
        select(IntelligenceItem, Source.name)
        .join(Source, Source.id == IntelligenceItem.source_id)
        .order_by(IntelligenceItem.created_at.desc())
    ).all()
    notes = db.execute(
        select(AnalystNote, User.username, IntelligenceItem.title)
        .join(User, User.id == AnalystNote.author_id)
        .join(IntelligenceItem, IntelligenceItem.id == AnalystNote.item_id)
        .order_by(AnalystNote.created_at.desc())
    ).all()
    return TEMPLATES.TemplateResponse(
        request,
        "correlation.html",
        _page_context(
            request,
            title="Correlation · Spook Shack",
            active_page="correlation",
            user=user,
            items=items,
            notes=notes,
            source_stats=db.execute(
                select(Source, func.count(IntelligenceItem.id))
                .outerjoin(IntelligenceItem, IntelligenceItem.source_id == Source.id)
                .group_by(Source.id)
                .order_by(Source.name)
            ).all(),
            summary=dashboard_summary_data(db),
            correlation=correlation_summary(db.connection().connection),
        ),
    )


@app.get("/correlation/cluster", response_class=HTMLResponse)
def correlation_cluster_detail(request: Request, cluster_type: str, cluster_value: str, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    cluster_key = f"{cluster_type}:{cluster_value}"
    cluster = db.execute(
        text("SELECT * FROM correlation_clusters WHERE cluster_key = :cluster_key"),
        {"cluster_key": cluster_key},
    ).mappings().one_or_none()
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    observations = db.execute(
        text(
            "SELECT * FROM correlation_observations WHERE cluster_key = :cluster_key ORDER BY created_at DESC LIMIT 25"
        ),
        {"cluster_key": cluster_key},
    ).mappings().all()
    links = db.execute(
        text(
            "SELECT * FROM correlation_links WHERE left_cluster_key = :cluster_key OR right_cluster_key = :cluster_key ORDER BY created_at DESC LIMIT 25"
        ),
        {"cluster_key": cluster_key},
    ).mappings().all()
    related_clusters = db.execute(
        text(
            "SELECT cluster_key, cluster_type, cluster_value, source_count, observation_count, score FROM correlation_clusters WHERE cluster_key IN (SELECT left_cluster_key FROM correlation_links WHERE right_cluster_key = :cluster_key UNION SELECT right_cluster_key FROM correlation_links WHERE left_cluster_key = :cluster_key) ORDER BY source_count DESC, observation_count DESC LIMIT 12"
        ),
        {"cluster_key": cluster_key},
    ).mappings().all()
    return TEMPLATES.TemplateResponse(
        request,
        "correlation_detail.html",
        _page_context(
            request,
            title=f"{cluster_type}:{cluster_value} · Correlation",
            active_page="correlation",
            user=user,
            cluster=cluster,
            observations=observations,
            links=links,
            related_clusters=related_clusters,
        ),
    )


@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    reports = db.execute(select(ForecastItem).order_by(ForecastItem.created_at.desc())).scalars().all()
    report_runs = db.execute(
        text("SELECT * FROM report_runs ORDER BY created_at DESC LIMIT :limit"),
        {"limit": 10},
    ).mappings().all()
    return TEMPLATES.TemplateResponse(
        request,
        "reports.html",
        _page_context(
            request,
            title="Reports · Spook Shack",
            active_page="reports",
            user=user,
            report_runs=report_runs,
            report_outline=get_report_outline(),
            forecasts=reports,
            summary=dashboard_summary_data(db),
        ),
    )


@app.get("/reports/new", response_class=HTMLResponse)
def reports_new_page(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    return TEMPLATES.TemplateResponse(
        request,
        "reports_new.html",
        _page_context(
            request,
            title="Build Report · Spook Shack",
            active_page="reports",
            user=user,
            report_outline=get_report_outline(),
        ),
    )


@app.get("/reports/{report_id}", response_class=HTMLResponse)
def report_detail_page(request: Request, report_id: str, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    report = db.execute(
        text("SELECT * FROM report_runs WHERE id = :report_id"),
        {"report_id": report_id},
    ).mappings().one_or_none()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return TEMPLATES.TemplateResponse(
        request,
        "report_detail.html",
        _page_context(
            request,
            title=f"{report['title']} · Spook Shack",
            active_page="reports",
            user=user,
            report=report,
            outline=get_report_outline(),
        ),
    )


@app.post("/reports/draft")
def draft_report(request: Request, cadence: str = Form("weekly"), db=Depends(get_db)):
    user = require_user(request, db)
    require_admin(user)
    report = create_report_draft(db, cadence, actor_role=user.role, created_by=user.username)
    return RedirectResponse(url=f"/reports?draft={report['id']}", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/forecast", response_class=HTMLResponse)
def forecast_page(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    forecast_cards = db.execute(select(ForecastItem).order_by(ForecastItem.created_at.desc())).scalars().all()
    briefs = db.execute(select(FutureTechBrief).order_by(FutureTechBrief.created_at.desc())).scalars().all()
    return TEMPLATES.TemplateResponse(
        request,
        "forecast.html",
        _page_context(
            request,
            title="Forecast · Spook Shack",
            active_page="forecast",
            user=user,
            forecast_cards=forecast_cards,
            future_briefs=[_future_brief_payload(brief) for brief in briefs],
            summary=dashboard_summary_data(db),
        ),
    )


@app.get("/forecast/new", response_class=HTMLResponse)
def forecast_new_page(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    return TEMPLATES.TemplateResponse(
        request,
        "forecast_new.html",
        _page_context(
            request,
            title="Import Forecast · Spook Shack",
            active_page="forecast",
            user=user,
        ),
    )


@app.get("/forecast/brief/{brief_id}", response_class=HTMLResponse)
def forecast_brief_detail(request: Request, brief_id: int, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    brief = db.get(FutureTechBrief, brief_id)
    if not brief:
        raise HTTPException(status_code=404, detail="Brief not found")
    return TEMPLATES.TemplateResponse(
        request,
        "forecast_detail.html",
        _page_context(
            request,
            title=f"{brief.title} · Spook Shack",
            active_page="forecast",
            user=user,
            brief=_future_brief_payload(brief),
        ),
    )


@app.post("/forecast/import")
def import_forecast(request: Request, payload: ForecastImportRequest, db=Depends(get_db)):
    user = require_user(request, db)
    require_admin(user)
    brief = FutureTechBrief(
        title=payload.title,
        classification=payload.classification,
        related_technology=payload.related_technology,
        existing_technology=payload.existing_technology,
        attack_vectors_json=json.dumps(payload.attack_vectors),
        threat_actor_use_json=json.dumps(payload.threat_actor_use),
        source_notes_json=json.dumps(payload.source_notes),
        summary=payload.summary,
        raw_report_json=json.dumps(payload.raw_report or {}, sort_keys=True),
        confidence=payload.confidence,
        updated_at=datetime.now(timezone.utc),
    )
    db.add(brief)
    db.commit()
    return {"ok": True, "brief": _future_brief_payload(brief)}


@app.post("/forecast/import-form")
def import_forecast_form(
    request: Request,
    title: str = Form(...),
    classification: str = Form(...),
    related_technology: str = Form(...),
    existing_technology: str = Form(...),
    attack_vectors_text: str = Form(""),
    threat_actor_use_text: str = Form(""),
    source_note: str = Form(""),
    summary: str = Form(""),
    confidence: int = Form(50),
    raw_report_json: str = Form(""),
    db=Depends(get_db),
):
    user = require_user(request, db)
    require_admin(user)
    raw_report = {}
    if raw_report_json.strip():
        try:
            raw_report = json.loads(raw_report_json)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid raw report JSON: {exc}") from exc
    brief = FutureTechBrief(
        title=title,
        classification=classification,
        related_technology=related_technology,
        existing_technology=existing_technology,
        attack_vectors_json=json.dumps([line.strip() for line in attack_vectors_text.splitlines() if line.strip()]),
        threat_actor_use_json=json.dumps([line.strip() for line in threat_actor_use_text.splitlines() if line.strip()]),
        source_notes_json=json.dumps([source_note.strip()] if source_note.strip() else []),
        summary=summary,
        raw_report_json=json.dumps(raw_report, sort_keys=True),
        confidence=max(0, min(100, confidence)),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(brief)
    db.commit()
    return RedirectResponse(url="/forecast", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/governance", response_class=HTMLResponse)
def governance_page(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    users = _users_summary(db)
    sources = db.execute(select(Source).order_by(Source.name)).scalars().all()
    return TEMPLATES.TemplateResponse(
        request,
        "governance.html",
        _page_context(
            request,
            title="Governance · Spook Shack",
            active_page="governance",
            user=user,
            users=users,
            sources=sources,
            summary=dashboard_summary_data(db),
        ),
    )


@app.get("/governance/users/{user_id}", response_class=HTMLResponse)
def governance_user_detail(request: Request, user_id: int, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    assigned_sources = db.execute(select(Source).order_by(Source.name)).scalars().all()
    return TEMPLATES.TemplateResponse(
        request,
        "governance_user.html",
        _page_context(
            request,
            title=f"{target.username} · Governance",
            active_page="governance",
            user=user,
            target=target,
            sources=assigned_sources,
            summary=dashboard_summary_data(db),
        ),
    )


@app.post("/governance/users/{user_id}/role")
def update_user_role(request: Request, user_id: int, role: str = Form(...), db=Depends(get_db)):
    user = require_user(request, db)
    require_admin(user)
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if role not in {"admin", "analyst"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    _role_update(target, role)
    db.add(target)
    db.commit()
    return RedirectResponse(url="/governance", status_code=status.HTTP_303_SEE_OTHER)


def dashboard_summary_data(db):
    source_count = db.execute(select(func.count(Source.id))).scalar_one()
    item_count = db.execute(select(func.count(IntelligenceItem.id))).scalar_one()
    tp = db.execute(select(func.count(IntelligenceItem.id)).where(IntelligenceItem.verdict == "true_positive")).scalar_one()
    fp = db.execute(select(func.count(IntelligenceItem.id)).where(IntelligenceItem.verdict == "false_positive")).scalar_one()
    unknown = db.execute(select(func.count(IntelligenceItem.id)).where(IntelligenceItem.verdict == "unknown")).scalar_one()
    return {
        "source_count": source_count,
        "item_count": item_count,
        "true_positive_count": tp,
        "false_positive_count": fp,
        "unknown_count": unknown,
        "future_brief_count": db.execute(select(func.count(FutureTechBrief.id))).scalar_one(),
    }


def _page_context(request: Request, *, title: str, active_page: str, user: User, **extra):
    return {
        "title": title,
        "active_page": active_page,
        "nav_links": NAV_LINKS,
        "user": user,
        **extra,
    }


_FEED_LINK_RE = re.compile(r'<link[^>]+rel=["\']alternate["\'][^>]+>', re.IGNORECASE)


def discover_source_candidates(url: str) -> dict[str, object]:
    response = httpx.get(url, timeout=20, follow_redirects=True, headers={"user-agent": "Spook Shack/CTI"})
    response.raise_for_status()
    html = response.text
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else urlsplit(url).netloc
    candidates: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in _FEED_LINK_RE.findall(html):
        type_match = re.search(r'type=["\']([^"\']+)["\']', match, re.IGNORECASE)
        href_match = re.search(r'href=["\']([^"\']+)["\']', match, re.IGNORECASE)
        if not href_match:
            continue
        href = urljoin(url, href_match.group(1))
        feed_type = (type_match.group(1).lower() if type_match else "feed")
        if any(marker in feed_type for marker in ("rss", "atom")) or href.endswith((".rss", ".atom", ".xml")):
            if href not in seen:
                candidates.append({"candidate_url": href, "candidate_type": feed_type})
                seen.add(href)
    for href in re.findall(r'href=["\']([^"\']+(?:rss|atom|feed|xml)[^"\']*)["\']', html, re.IGNORECASE):
        full = urljoin(url, href)
        if full not in seen:
            candidates.append({"candidate_url": full, "candidate_type": "heuristic"})
            seen.add(full)
    return {"query_url": url, "title": title, "candidates": candidates}


def _future_brief_payload(brief: FutureTechBrief) -> dict[str, object]:
    return {
        "id": brief.id,
        "title": brief.title,
        "classification": brief.classification,
        "related_technology": brief.related_technology,
        "existing_technology": brief.existing_technology,
        "attack_vectors": json.loads(brief.attack_vectors_json or "[]"),
        "threat_actor_use": json.loads(brief.threat_actor_use_json or "[]"),
        "source_notes": json.loads(brief.source_notes_json or "[]"),
        "summary": brief.summary,
        "confidence": brief.confidence,
        "created_at": brief.created_at,
        "updated_at": brief.updated_at,
    }


def _role_update(user: User, role: str) -> None:
    user.role = role


def _users_summary(db):
    users = db.execute(select(User).order_by(User.username)).scalars().all()
    return [
        {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "created_at": user.created_at,
        }
        for user in users
    ]


@app.exception_handler(HTTPException)
def http_exception_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    if exc.status_code == 401:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
