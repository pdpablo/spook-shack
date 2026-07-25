from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="analyst", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    notes = relationship("AnalystNote", back_populates="author")


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), default="feed", nullable=False)
    url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    access_method: Mapped[str] = mapped_column(String(64), default="api", nullable=False)
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    schedule: Mapped[str] = mapped_column(String(64), default="*/30 * * * *", nullable=False)
    policy_notes: Mapped[str] = mapped_column(Text, default="Comply with source AUP and rate limits.", nullable=False)
    encrypted_credentials: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    items = relationship("IntelligenceItem", back_populates="source")


class IntelligenceItem(Base):
    __tablename__ = "items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    observable_type: Mapped[str] = mapped_column(String(64), default="indicator", nullable=False)
    observable_value: Mapped[str] = mapped_column(String(512), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    verdict: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    raw_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    source = relationship("Source", back_populates="items")
    notes = relationship("AnalystNote", back_populates="item", cascade="all, delete-orphan")


class AnalystNote(Base):
    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"), nullable=False)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    note: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    item = relationship("IntelligenceItem", back_populates="notes")
    author = relationship("User", back_populates="notes")


class ForecastItem(Base):
    __tablename__ = "forecasts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    technology_class: Mapped[str] = mapped_column(String(128), nullable=False)
    related_technology: Mapped[str] = mapped_column(String(256), nullable=False)
    attack_surface: Mapped[str] = mapped_column(Text, nullable=False)
    threat_use: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
