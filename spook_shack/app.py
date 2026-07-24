from __future__ import annotations

from html import escape
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from dashboard.plugin_api import router as spook_shack_router
from spook_shack import service
from spook_shack.bootstrap import bootstrap_credentials_from_env
from spook_shack.intel import ensure_intel_schema


def _safe(value: Any) -> str:
    return escape("" if value is None else str(value))


def _render_badge(label: str, value: Any) -> str:
    return (
        "<div class='badge'>"
        f"<span>{_safe(label)}</span>"
        f"<strong>{_safe(value)}</strong>"
        "</div>"
    )


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>{_safe(title)}</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ margin: 0; font-family: Inter, system-ui, sans-serif; background: #0b1220; color: #e5eefc; }}
    a {{ color: #7dd3fc; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .wrap {{ max-width: 1280px; margin: 0 auto; padding: 24px; }}
    .hero {{ background: linear-gradient(135deg, #101b34, #13213f); border: 1px solid #243452; border-radius: 18px; padding: 24px; }}
    .hero h1 {{ margin: 0 0 8px; font-size: 2rem; }}
    .hero p {{ margin: 0; color: #b6c5dd; line-height: 1.6; }}
    .grid {{ display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); margin-top: 18px; }}
    .card {{ background: #10192d; border: 1px solid #22314f; border-radius: 16px; padding: 18px; }}
    .card h2, .card h3 {{ margin: 0 0 12px; }}
    .muted {{ color: #9fb0cb; }}
    .badges {{ display: flex; flex-wrap: wrap; gap: 12px; }}
    .badge {{ background: #0e1730; border: 1px solid #22314f; border-radius: 12px; padding: 12px 14px; min-width: 140px; }}
    .badge span {{ display: block; font-size: 0.78rem; color: #9fb0cb; text-transform: uppercase; letter-spacing: .08em; }}
    .badge strong {{ display: block; margin-top: 6px; font-size: 1.15rem; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 10px 8px; border-bottom: 1px solid #22314f; vertical-align: top; }}
    th {{ color: #9fb0cb; font-weight: 600; font-size: .92rem; }}
    .section {{ margin-top: 20px; }}
    .pill {{ display: inline-block; padding: 4px 10px; border-radius: 999px; background: #16233d; border: 1px solid #243452; font-size: .82rem; margin-right: 6px; }}
    pre {{ white-space: pre-wrap; word-wrap: break-word; background: #09101d; border: 1px solid #22314f; padding: 12px; border-radius: 12px; overflow-x: auto; }}
    ul {{ margin: 0; padding-left: 20px; }}
    li + li {{ margin-top: 6px; }}
    .two-col {{ display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }}
    .footer {{ margin-top: 24px; color: #8fa3c6; font-size: .9rem; }}
  </style>
</head>
<body>
  <div class='wrap'>
    {body}
  </div>
</body>
</html>"""


def _dashboard_body(overview: dict[str, Any], correlation: dict[str, Any]) -> str:
    counts = overview.get("counts", {})
    sources = overview.get("sources", [])
    runs = overview.get("runs", [])
    notes = overview.get("notes", [])
    reports = overview.get("reports", [])
    roadmap = overview.get("roadmap", [])
    outline = overview.get("report_outline", [])
    source_rows = "".join(
        "<tr>"
        f"<td><a href='/sources/{_safe(src['source_key'])}'>{_safe(src['display_name'])}</a></td>"
        f"<td>{_safe(src['source_type'])}</td>"
        f"<td>{_safe(src['schedule'])}</td>"
        f"<td>{'yes' if src.get('enabled') else 'no'}</td>"
        f"<td>{_safe(src.get('last_run_status') or 'never')}</td>"
        f"<td>{_safe(src.get('policy_note') or '')}</td>"
        "</tr>"
        for src in sources
    )
    run_rows = "".join(
        "<tr>"
        f"<td>{_safe(run['source_key'])}</td>"
        f"<td>{_safe(run['status'])}</td>"
        f"<td>{_safe(run['records_seen'])}</td>"
        f"<td>{_safe(run['records_normalized'])}</td>"
        f"<td>{_safe(run.get('reason') or '')}</td>"
        f"<td>{_safe(run['created_at'])}</td>"
        "</tr>"
        for run in runs[:10]
    )
    note_rows = "".join(
        "<tr>"
        f"<td>{_safe(note['target_type'])}</td>"
        f"<td>{_safe(note['target_id'])}</td>"
        f"<td>{_safe(note['verdict'])}</td>"
        f"<td>{_safe(note.get('created_by') or '')}</td>"
        f"<td>{_safe(note.get('note') or '')}</td>"
        "</tr>"
        for note in notes[:8]
    )
    report_rows = "".join(
        "<tr>"
        f"<td>{_safe(report['cadence'])}</td>"
        f"<td>{_safe(report['status'])}</td>"
        f"<td>{_safe(report['title'])}</td>"
        f"<td>{_safe(report['created_at'])}</td>"
        "</tr>"
        for report in reports[:5]
    )
    roadmap_items = "".join(
        f"<li><strong>{_safe(item['title'])}</strong> — {_safe(item['summary'])}</li>"
        for item in roadmap
    )
    outline_items = "".join(f"<li>{_safe(item)}</li>" for item in outline)
    top_clusters = correlation.get("top_clusters", [])
    cluster_rows = "".join(
        "<tr>"
        f"<td>{_safe(cluster['cluster_type'])}</td>"
        f"<td>{_safe(cluster['cluster_value'])}</td>"
        f"<td>{_safe(cluster['source_count'])}</td>"
        f"<td>{_safe(cluster['observation_count'])}</td>"
        f"<td>{_safe(round(float(cluster['score']), 3))}</td>"
        "</tr>"
        for cluster in top_clusters[:8]
    )

    return f"""
    <section class='hero'>
      <h1>Spook Shack</h1>
      <p>Threat-intelligence workspace for queued ingestion, analyst notes, encrypted source credentials, correlation, and draft reporting.</p>
      <div class='section badges'>
        {_render_badge('Sources', counts.get('sources', 0))}
        {_render_badge('Enabled', counts.get('enabled_sources', 0))}
        {_render_badge('Queued Runs', counts.get('queued_runs', 0))}
        {_render_badge('Observables', counts.get('observables', 0))}
        {_render_badge('Raw Records', counts.get('raw_records', 0))}
        {_render_badge('Reports', counts.get('reports', 0))}
      </div>
      <p class='footer'>Access control is role-based through the <code>X-Spook-Shack-Role</code> header. Admin users can manage sources, queue ingestion, and store credentials; analysts can review dashboards, add verdict notes, and draft reports.</p>
    </section>

    <div class='grid'>
      <div class='card'>
        <h2>Correlation</h2>
        <p class='muted'>Cross-source clusters and links already normalized into reusable observables.</p>
        <div class='badges'>
          {_render_badge('Clusters', correlation.get('clusters_total', 0))}
          {_render_badge('Shared', correlation.get('shared_clusters', 0))}
          {_render_badge('Links', correlation.get('links_total', 0))}
        </div>
      </div>
      <div class='card'>
        <h2>Reports</h2>
        <p class='muted'>Weekly, monthly, quarterly, and annual CTI drafts follow the Zeltser outline.</p>
        <ul>{outline_items}</ul>
      </div>
    </div>

    <div class='section card'>
      <h2>Source dashboards</h2>
      <table>
        <thead><tr><th>Source</th><th>Type</th><th>Schedule</th><th>Enabled</th><th>Last run</th><th>Policy note</th></tr></thead>
        <tbody>{source_rows or '<tr><td colspan="6" class="muted">No sources configured yet.</td></tr>'}</tbody>
      </table>
    </div>

    <div class='two-col section'>
      <div class='card'>
        <h2>Recent ingestion runs</h2>
        <table>
          <thead><tr><th>Source</th><th>Status</th><th>Seen</th><th>Normalized</th><th>Reason</th><th>When</th></tr></thead>
          <tbody>{run_rows or '<tr><td colspan="6" class="muted">No ingestion runs yet.</td></tr>'}</tbody>
        </table>
      </div>
      <div class='card'>
        <h2>Analyst notes</h2>
        <table>
          <thead><tr><th>Target</th><th>ID</th><th>Verdict</th><th>By</th><th>Note</th></tr></thead>
          <tbody>{note_rows or '<tr><td colspan="5" class="muted">No notes yet.</td></tr>'}</tbody>
        </table>
      </div>
    </div>

    <div class='two-col section'>
      <div class='card'>
        <h2>Report drafts</h2>
        <table>
          <thead><tr><th>Cadence</th><th>Status</th><th>Title</th><th>Created</th></tr></thead>
          <tbody>{report_rows or '<tr><td colspan="4" class="muted">No drafts yet.</td></tr>'}</tbody>
        </table>
      </div>
      <div class='card'>
        <h2>Top correlation clusters</h2>
        <table>
          <thead><tr><th>Type</th><th>Value</th><th>Sources</th><th>Observations</th><th>Score</th></tr></thead>
          <tbody>{cluster_rows or '<tr><td colspan="5" class="muted">No clustered observables yet.</td></tr>'}</tbody>
        </table>
      </div>
    </div>

    <div class='section card'>
      <h2>Roadmap</h2>
      <ul>{roadmap_items}</ul>
    </div>
    """


def _source_dashboard_body(source: dict[str, Any], stats: dict[str, Any], runs: list[dict[str, Any]], notes: list[dict[str, Any]], raw_records: list[dict[str, Any]], observables: list[dict[str, Any]]) -> str:
    run_rows = "".join(
        "<tr>"
        f"<td>{_safe(run['status'])}</td>"
        f"<td>{_safe(run['mode'])}</td>"
        f"<td>{_safe(run['records_seen'])}</td>"
        f"<td>{_safe(run['records_normalized'])}</td>"
        f"<td>{_safe(run.get('reason') or '')}</td>"
        f"<td>{_safe(run['created_at'])}</td>"
        "</tr>"
        for run in runs
    )
    note_rows = "".join(
        "<tr>"
        f"<td>{_safe(note['verdict'])}</td>"
        f"<td>{_safe(note.get('created_by') or '')}</td>"
        f"<td>{_safe(note.get('note') or '')}</td>"
        f"<td>{_safe(note['created_at'])}</td>"
        "</tr>"
        for note in notes
    )
    raw_rows = "".join(
        "<tr>"
        f"<td>{_safe(record.get('external_id') or '')}</td>"
        f"<td>{_safe(record.get('source_url') or '')}</td>"
        f"<td>{_safe(record.get('fetched_at') or '')}</td>"
        f"<td><pre>{_safe((record.get('payload_json') or '')[:320])}</pre></td>"
        "</tr>"
        for record in raw_records
    )
    observable_rows = "".join(
        "<tr>"
        f"<td>{_safe(obs['observable_type'])}</td>"
        f"<td>{_safe(obs['observable_value'])}</td>"
        f"<td>{_safe(obs['confidence'])}</td>"
        f"<td>{_safe(obs['created_at'])}</td>"
        "</tr>"
        for obs in observables
    )
    return f"""
    <section class='hero'>
      <p><a href='/'>← Back to universal dashboard</a></p>
      <h1>{_safe(source['display_name'])}</h1>
      <p>{_safe(source['policy_note'])}</p>
      <div class='section badges'>
        {_render_badge('Type', source['source_type'])}
        {_render_badge('Schedule', source['schedule'])}
        {_render_badge('Enabled', 'yes' if source.get('enabled') else 'no')}
        {_render_badge('Has credentials', 'yes' if source.get('has_credentials') else 'no')}
        {_render_badge('Raw records', stats['raw_records'])}
        {_render_badge('Observables', stats['observables'])}
      </div>
      <p class='footer'>Admin users can update this source through the JSON API at <code>/api/plugins/spook-shack/sources</code>. Analysts can review notes and draft reports from the same API surface.</p>
    </section>

    <div class='grid'>
      <div class='card'>
        <h2>Ingestion stats</h2>
        <ul>
          <li>Last run: {_safe(source.get('last_run_status') or 'never')}</li>
          <li>Last run at: {_safe(source.get('last_run_at') or 'never')}</li>
          <li>Last error: {_safe(source.get('last_error') or 'none')}</li>
          <li>Policy note: {_safe(source.get('policy_note') or '')}</li>
          <li>Rate limit note: {_safe(source.get('rate_limit_note') or '')}</li>
        </ul>
      </div>
      <div class='card'>
        <h2>Correlation snapshot</h2>
        <div class='badges'>
          {_render_badge('Top observables', stats['observable_types'])}
          {_render_badge('Shared clusters', stats['shared_clusters'])}
          {_render_badge('Total runs', stats['runs_total'])}
          {_render_badge('Current notes', stats['notes_total'])}
        </div>
      </div>
    </div>

    <div class='two-col section'>
      <div class='card'>
        <h2>Recent runs</h2>
        <table>
          <thead><tr><th>Status</th><th>Mode</th><th>Seen</th><th>Normalized</th><th>Reason</th><th>When</th></tr></thead>
          <tbody>{run_rows or '<tr><td colspan="6" class="muted">No runs for this source yet.</td></tr>'}</tbody>
        </table>
      </div>
      <div class='card'>
        <h2>Analyst notes</h2>
        <table>
          <thead><tr><th>Verdict</th><th>By</th><th>Note</th><th>When</th></tr></thead>
          <tbody>{note_rows or '<tr><td colspan="4" class="muted">No source notes yet.</td></tr>'}</tbody>
        </table>
      </div>
    </div>

    <div class='two-col section'>
      <div class='card'>
        <h2>Recent raw records</h2>
        <table>
          <thead><tr><th>External ID</th><th>Source URL</th><th>Fetched</th><th>Payload excerpt</th></tr></thead>
          <tbody>{raw_rows or '<tr><td colspan="4" class="muted">No raw records yet.</td></tr>'}</tbody>
        </table>
      </div>
      <div class='card'>
        <h2>Recent observables</h2>
        <table>
          <thead><tr><th>Type</th><th>Value</th><th>Confidence</th><th>When</th></tr></thead>
          <tbody>{observable_rows or '<tr><td colspan="4" class="muted">No observables yet.</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    """


def create_app() -> FastAPI:
    app = FastAPI(title="Spook Shack MVP")

    @app.on_event("startup")
    def _startup() -> None:
        with service.connect() as conn:
            ensure_intel_schema(conn)
            bootstrap_credentials_from_env(conn)

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> HTMLResponse:
        with service.connect() as conn:
            ensure_intel_schema(conn)
            overview = service.get_overview(conn, role="analyst")
            correlation = service.get_correlation_summary(conn)
        body = _dashboard_body(overview, correlation)
        return HTMLResponse(_page("Spook Shack Dashboard", body))

    @app.get("/sources/{source_key}", response_class=HTMLResponse)
    def source_dashboard(source_key: str) -> HTMLResponse:
        with service.connect() as conn:
            ensure_intel_schema(conn)
            try:
                source = service.get_source(conn, source_key)
            except KeyError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            stats = {
                "raw_records": conn.execute("SELECT COUNT(*) FROM raw_records WHERE source_key = ?", (source_key,)).fetchone()[0] or 0,
                "observables": conn.execute("SELECT COUNT(*) FROM normalized_observables WHERE source_key = ?", (source_key,)).fetchone()[0] or 0,
                "shared_clusters": conn.execute(
                    "SELECT COUNT(DISTINCT cluster_key) FROM correlation_observations WHERE source_key = ? AND cluster_key IN (SELECT cluster_key FROM correlation_clusters WHERE source_count > 1)",
                    (source_key,),
                ).fetchone()[0] or 0,
                "runs_total": conn.execute("SELECT COUNT(*) FROM ingestion_runs WHERE source_key = ?", (source_key,)).fetchone()[0] or 0,
                "notes_total": conn.execute("SELECT COUNT(*) FROM analyst_notes WHERE target_type = 'source' AND target_id = ?", (source_key,)).fetchone()[0] or 0,
                "observable_types": ", ".join(
                    f"{row['observable_type']} ({row['total']})"
                    for row in conn.execute(
                        "SELECT observable_type, COUNT(*) AS total FROM normalized_observables WHERE source_key = ? GROUP BY observable_type ORDER BY total DESC, observable_type ASC LIMIT 5",
                        (source_key,),
                    ).fetchall()
                ) or "none",
            }
            runs = [dict(row) for row in conn.execute("SELECT * FROM ingestion_runs WHERE source_key = ? ORDER BY created_at DESC LIMIT 5", (source_key,)).fetchall()]
            notes = [dict(row) for row in conn.execute("SELECT * FROM analyst_notes WHERE target_type = 'source' AND target_id = ? ORDER BY created_at DESC LIMIT 5", (source_key,)).fetchall()]
            raw_records = [dict(row) for row in conn.execute("SELECT * FROM raw_records WHERE source_key = ? ORDER BY created_at DESC LIMIT 5", (source_key,)).fetchall()]
            observables = [dict(row) for row in conn.execute("SELECT * FROM normalized_observables WHERE source_key = ? ORDER BY created_at DESC LIMIT 8", (source_key,)).fetchall()]
        body = _source_dashboard_body(source, stats, runs, notes, raw_records, observables)
        return HTMLResponse(_page(f"Spook Shack — {source['display_name']}", body))

    app.include_router(spook_shack_router, prefix="/api/plugins/spook-shack")
    return app


app = create_app()
