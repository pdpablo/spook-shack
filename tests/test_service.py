from __future__ import annotations

import importlib
import asyncio

import httpx
import pytest
from fastapi import FastAPI

from spook_shack import service
from spook_shack import intel


@pytest.fixture()
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SPOOK_SHACK_HOME", str(tmp_path / "spook-shack"))
    importlib.reload(service)
    importlib.reload(intel)
    yield
    importlib.reload(service)
    importlib.reload(intel)


def _app() -> FastAPI:
    plugin_api = importlib.import_module("dashboard.plugin_api")
    app = FastAPI()
    app.include_router(plugin_api.router, prefix="/api/plugins/spook-shack")
    return app


async def _arequest(app: FastAPI, method: str, path: str, **kwargs) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.request(method, path, **kwargs)


def _request(app: FastAPI, method: str, path: str, **kwargs) -> httpx.Response:
    return asyncio.run(_arequest(app, method, path, **kwargs))


def test_dashboard_routes_render(isolated_home):
    from app.db import Base, SessionLocal, engine
    from app.main import app as full_app, seed_demo_data

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_demo_data(db)

    async def run():
        transport = httpx.ASGITransport(app=full_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=True) as client:
            login = await client.post(
                "/login",
                data={"username": "admin", "password": "spookshack-admin"},
            )
            assert login.status_code == 200
            response = await client.get("/")
            sources_response = await client.get("/api/sources")
            return response, sources_response

    response, sources_response = asyncio.run(run())

    assert response.status_code == 200
    assert "Universal Intelligence Dashboard" in response.text
    assert "Sources" in response.text
    assert sources_response.status_code == 200
    assert "ransomware.live" in sources_response.text


def test_dashboard_search_filters_and_sort(isolated_home):
    from app.db import Base, SessionLocal, engine
    from app.main import app as full_app, seed_demo_data

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_demo_data(db)

    async def run():
        transport = httpx.ASGITransport(app=full_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver", follow_redirects=True) as client:
            await client.post("/login", data={"username": "admin", "password": "spookshack-admin"})
            response = await client.get(
                "/",
                params={"q": "phish", "verdict": "true_positive", "sort": "highest_confidence"},
            )
            return response

    response = asyncio.run(run())

    assert response.status_code == 200
    assert "New phishing lure" in response.text
    assert "ALPHV leak post" not in response.text


def test_seeds_default_sources_and_roadmap(isolated_home):
    with service.connect() as conn:
        sources = service.list_sources(conn)
        overview = service.get_overview(conn, role="analyst")

    assert {item["source_key"] for item in sources} == {
        "ransomware.live",
        "telegram-leaks",
        "tweetfeed",
        "phishhunt",
        "haveibeenpwned",
    }
    assert overview["counts"]["sources"] == 5
    assert len(overview["roadmap"]) == 5
    assert overview["report_outline"][0] == "Executive Summary"


def test_encrypts_credentials_and_round_trips(isolated_home):
    with service.connect() as conn:
        result = service.set_source_credentials(
            conn,
            "haveibeenpwned",
            {"api_key": "super-secret"},
            actor_role="admin",
        )
        token = conn.execute(
            "SELECT encrypted_credentials FROM source_definitions WHERE source_key = ?",
            ("haveibeenpwned",),
        ).fetchone()[0]
        decrypted = service.get_source_credentials(conn, "haveibeenpwned")

    assert result["credential_state"] == "encrypted"
    assert "super-secret" not in token
    assert decrypted == {"api_key": "super-secret"}


def test_admin_gate_blocks_source_upsert_and_queue(isolated_home):
    response = asyncio.run(
        _arequest(
            _app(),
            "POST",
            "/api/plugins/spook-shack/sources",
            headers={"X-Spook-Shack-Role": "analyst"},
            json={"source_key": "example", "display_name": "Example", "source_type": "api"},
        )
    )
    assert response.status_code == 403

    admin_response = asyncio.run(
        _arequest(
            _app(),
            "POST",
            "/api/plugins/spook-shack/sources",
            headers={"X-Spook-Shack-Role": "admin"},
            json={
                "source_key": "example",
                "display_name": "Example",
                "source_type": "api",
                "policy_note": "demo",
                "rate_limit_note": "demo",
            },
        )
    )
    assert admin_response.status_code == 200
    assert admin_response.json()["source"]["source_key"] == "example"

    queue_response = asyncio.run(
        _arequest(
            _app(),
            "POST",
            "/api/plugins/spook-shack/sources/example/queue",
            headers={"X-Spook-Shack-Role": "analyst"},
            json={"reason": "nope"},
        )
    )
    assert queue_response.status_code == 403


def test_real_connectors_feed_the_correlation_engine(isolated_home):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith("https://api.ransomware.live/v2/recentvictims"):
            return httpx.Response(
                200,
                json=[
                    {
                        "victim": "Shared Example Ltd",
                        "group": "Qilin",
                        "attackdate": "2026-07-21",
                        "country": "US",
                        "press": [{"url": "https://phish.example/news"}],
                        "updates": [],
                    }
                ],
            )
        if url.startswith("https://phishunt.io/api/v1/domains"):
            return httpx.Response(
                200,
                json={
                    "count": 1,
                    "results": [
                        {
                            "url": "https://phish.example/login",
                            "domain": "phish.example",
                            "company": "shared example",
                            "date": "2026-07-21T00:00:00+00:00",
                            "first_seen": "2026-07-20T00:00:00+00:00",
                            "ip": "198.51.100.42",
                            "asn": "64496",
                            "org": "Example Hosting",
                            "cert": "Let's Encrypt",
                            "malicious_google": True,
                        }
                    ],
                },
            )
        if url.startswith("https://tweetfeed.live/rss.xml"):
            rss = """<?xml version='1.0' encoding='UTF-8'?>
<rss version='2.0'>
  <channel>
    <title>TweetFeed</title>
    <item>
      <title>IOC drop</title>
      <link>https://phish.example/login</link>
      <guid>tweetfeed-1</guid>
      <pubDate>Mon, 21 Jul 2026 00:00:00 GMT</pubDate>
      <description>Malicious URL https://phish.example/login and host phish.example</description>
    </item>
  </channel>
</rss>"""
            return httpx.Response(200, content=rss.encode("utf-8"), headers={"content-type": "application/rss+xml"})
        if url.startswith("https://haveibeenpwned.com/api/v3/breaches"):
            return httpx.Response(
                200,
                json=[
                    {
                        "Name": "SharedExample",
                        "Title": "Shared Example Breach",
                        "Domain": "phish.example",
                        "BreachDate": "2025-01-01",
                        "AddedDate": "2025-01-02",
                        "DataClasses": ["Email addresses", "Passwords"],
                    }
                ],
            )
        raise AssertionError(f"unexpected request: {url}")

    transport = httpx.MockTransport(handler)

    with service.connect() as conn:
        intel.ensure_intel_schema(conn)
        results = intel.ingest_all_sources(conn, actor_role="admin", transport=transport)
        summary = intel.correlation_summary(conn)
        clusters = intel.cluster_rows(conn, limit=10)
        links = intel.link_rows(conn, limit=10)
        raw_count = conn.execute("SELECT COUNT(*) FROM raw_records").fetchone()[0]
        obs_count = conn.execute("SELECT COUNT(*) FROM normalized_observables").fetchone()[0]

    assert any(item["status"] == "success" for item in results)
    assert raw_count >= 3
    assert obs_count >= 3
    assert summary["shared_clusters"] >= 1
    assert any(cluster["cluster_value"] == "phish.example" and cluster["source_count"] >= 3 for cluster in clusters)
    assert any(link["relation_type"] in {"url_domain", "domain_apex_domain", "email_domain", "same_record"} for link in links)


def test_overview_and_correlation_endpoint_reflect_ingested_data(isolated_home):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith("https://api.ransomware.live/v2/recentvictims"):
            return httpx.Response(200, json=[])
        if url.startswith("https://phishunt.io/api/v1/domains"):
            return httpx.Response(200, json={"count": 0, "results": []})
        if url.startswith("https://tweetfeed.live/rss.xml"):
            rss = """<?xml version='1.0' encoding='UTF-8'?><rss version='2.0'><channel><title>TweetFeed</title></channel></rss>"""
            return httpx.Response(200, content=rss.encode("utf-8"), headers={"content-type": "application/rss+xml"})
        if url.startswith("https://haveibeenpwned.com/api/v3/breaches"):
            return httpx.Response(200, json=[])
        raise AssertionError(f"unexpected request: {url}")

    transport = httpx.MockTransport(handler)

    with service.connect() as conn:
        intel.ensure_intel_schema(conn)
        intel.ingest_all_sources(conn, actor_role="admin", transport=transport)

    response = asyncio.run(
        _arequest(
            _app(),
            "GET",
            "/api/plugins/spook-shack/overview",
            headers={"X-Spook-Shack-Role": "analyst"},
        )
    )
    correlation = asyncio.run(_arequest(_app(), "GET", "/api/plugins/spook-shack/correlation"))

    assert response.status_code == 200
    assert "correlation" in response.json()
    assert correlation.status_code == 200
    assert "summary" in correlation.json()
