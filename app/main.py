from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from starlette.middleware.sessions import SessionMiddleware

from .db import Base, SessionLocal, engine
from .models import AnalystNote, ForecastItem, IntelligenceItem, Source, User
from .schemas import ItemCreate, LoginRequest, NoteCreate, SourceCreate, VerdictUpdate
from .security import DemoCredentials, hash_password, new_token, verify_password

BASE_DIR = Path(__file__).resolve().parents[1]
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))
STATIC_DIR = BASE_DIR / "static"
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "dev-only-change-me")
DEMO = DemoCredentials()

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


def seed_demo_data(db):
    if not db.execute(select(User).limit(1)).scalar_one_or_none():
        db.add(User(username=DEMO.admin_username, password_hash=hash_password(DEMO.admin_password), role="admin"))
        db.add(User(username=DEMO.analyst_username, password_hash=hash_password(DEMO.analyst_password), role="analyst"))
        db.commit()

    if not db.execute(select(Source).limit(1)).scalar_one_or_none():
        sources = [
            Source(name="ransomware.live", source_type="feed", url="https://ransomware.live", access_method="api", rate_limit_per_minute=30, schedule="*/30 * * * *", policy_notes="Use public endpoints and obey rate limits."),
            Source(name="Telegram Leaks", source_type="messaging", url="https://telegram.org", access_method="approved_client", rate_limit_per_minute=20, schedule="0 * * * *", policy_notes="Only ingest channels the operator is authorized to access."),
            Source(name="TweetFeed", source_type="social", url="https://x.com", access_method="api", rate_limit_per_minute=15, schedule="*/20 * * * *", policy_notes="Use official or permitted access methods only."),
            Source(name="PhishHunt", source_type="feed", url="https://phishunt.io", access_method="api", rate_limit_per_minute=30, schedule="*/15 * * * *", policy_notes="Respect feed terms and documented limits."),
            Source(name="HaveIBeenPwned", source_type="api", url="https://haveibeenpwned.com", access_method="api", rate_limit_per_minute=4, schedule="0 */6 * * *", policy_notes="Use the official API and its rate limits."),
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

    if not db.execute(select(IntelligenceItem).limit(1)).scalar_one_or_none():
        seed_items(db)


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_demo_data(db)


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
            "demo_admin": DEMO.admin_username,
            "demo_analyst": DEMO.analyst_username,
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
                "demo_admin": DEMO.admin_username,
                "demo_analyst": DEMO.analyst_username,
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
def dashboard(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    sources = db.execute(select(Source).order_by(Source.name)).scalars().all()
    items = db.execute(
        select(IntelligenceItem, Source.name)
        .join(Source, Source.id == IntelligenceItem.source_id)
        .order_by(IntelligenceItem.created_at.desc())
        .limit(20)
    ).all()
    forecasts = db.execute(select(ForecastItem).order_by(ForecastItem.created_at.desc())).scalars().all()
    summary = dashboard_summary_data(db)

    rendered_items = []
    for item, source_name in items:
        note_rows = db.execute(
            select(AnalystNote, User.username)
            .join(User, User.id == AnalystNote.author_id)
            .where(AnalystNote.item_id == item.id)
            .order_by(AnalystNote.created_at.desc())
        ).all()
        rendered_items.append((item, source_name, note_rows))

    return TEMPLATES.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "sources": sources,
            "items": rendered_items,
            "forecasts": forecasts,
            "summary": summary,
        },
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
            "access_method": source.access_method,
            "rate_limit_per_minute": source.rate_limit_per_minute,
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
        access_method=payload.access_method,
        rate_limit_per_minute=payload.rate_limit_per_minute,
        schedule=payload.schedule,
        policy_notes=payload.policy_notes,
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
    access_method: str = Form("api"),
    rate_limit_per_minute: int = Form(60),
    schedule: str = Form("*/30 * * * *"),
    policy_notes: str = Form("Comply with source AUP and rate limits."),
    db=Depends(get_db),
):
    user = require_user(request, db)
    require_admin(user)
    source = Source(
        name=name,
        source_type=source_type,
        url=url,
        access_method=access_method,
        rate_limit_per_minute=rate_limit_per_minute,
        schedule=schedule,
        policy_notes=policy_notes,
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


@app.post("/demo/ingest")
def demo_ingest(request: Request, db=Depends(get_db)):
    user = require_user(request, db)
    if user.role not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Not allowed")
    source = db.execute(select(Source).where(Source.name == "TweetFeed")).scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Seed source missing")
    now = datetime.now(timezone.utc)
    item = IntelligenceItem(
        source_id=source.id,
        title=f"Live ingest snapshot {now:%Y-%m-%d %H:%M}",
        summary="Simulated source update for Raspberry Pi testing and dashboard growth.",
        observable_type="keyword",
        observable_value="simulated cluster",
        confidence=55,
        verdict="unknown",
        raw_excerpt="Simulated source update for Raspberry Pi testing and dashboard growth.",
    )
    source.last_sync_at = now
    db.add(item)
    db.add(source)
    db.commit()
    return {"ok": True, "item_id": item.id}


@app.post("/api/bootstrap")
def api_bootstrap(request: Request, db=Depends(get_db)):
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    seed_demo_data(db)
    return {"ok": True}


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
    }


@app.exception_handler(HTTPException)
def http_exception_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    if exc.status_code == 401:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
