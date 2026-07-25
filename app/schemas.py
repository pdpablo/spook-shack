from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class SourceCreate(BaseModel):
    name: str
    source_type: str = "feed"
    url: str | None = None
    access_method: str = "api"
    rate_limit_per_minute: int = Field(default=60, ge=1)
    schedule: str = "*/30 * * * *"
    policy_notes: str = "Comply with source AUP and rate limits."


class ItemCreate(BaseModel):
    source_id: int
    title: str
    summary: str
    observable_type: str = "indicator"
    observable_value: str
    confidence: int = Field(default=50, ge=0, le=100)
    raw_excerpt: str | None = None


class NoteCreate(BaseModel):
    note: str


class VerdictUpdate(BaseModel):
    verdict: str = Field(pattern="^(true_positive|false_positive|unknown)$")


class DashboardSource(BaseModel):
    id: int
    name: str
    source_type: str
    url: str | None
    rate_limit_per_minute: int
    schedule: str
    enabled: bool
    last_sync_at: datetime | None


class DashboardItem(BaseModel):
    id: int
    title: str
    summary: str
    observable_type: str
    observable_value: str
    confidence: int
    verdict: str
    source_name: str
    created_at: datetime


class DashboardSummary(BaseModel):
    source_count: int
    item_count: int
    true_positive_count: int
    false_positive_count: int
    unknown_count: int
