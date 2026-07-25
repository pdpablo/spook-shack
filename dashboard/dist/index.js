(function () {
  "use strict";
  const SDK = window.__HERMES_PLUGIN_SDK__;
  if (!SDK || !window.__HERMES_PLUGINS__) return;
  const React = SDK.React;
  const h = React.createElement;
  const { useEffect, useMemo, useState, useCallback } = SDK.hooks;
  const { Card, CardContent, CardHeader, CardTitle, Badge, Button, Input } = SDK.components;

  function parseError(err) {
    const raw = err && err.message ? String(err.message) : String(err || "error");
    const match = raw.match(/^\d{3}:\s*(.*)$/s);
    const body = match ? match[1] : raw;
    try {
      const parsed = JSON.parse(body);
      if (parsed && typeof parsed.detail === "string") return parsed.detail;
    } catch (_) {}
    return body;
  }

  function App() {
    const [role, setRole] = useState("admin");
    const [cadence, setCadence] = useState("weekly");
    const [form, setForm] = useState({ source_key: "", display_name: "", source_type: "api", ingestion_mode: "scheduled poll", schedule: "0 * * * *", rate_limit_note: "", policy_note: "", credential_hint: "", enabled: true });
    const [data, setData] = useState(null);
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [queued, setQueued] = useState("");

    const load = useCallback(async () => {
      setLoading(true);
      setError("");
      try {
        const res = await SDK.fetchJSON("/api/plugins/spook-shack/overview", { headers: { "X-Spook-Shack-Role": role } });
        setData(res);
      } catch (err) {
        setError(parseError(err));
      } finally {
        setLoading(false);
      }
    }, [role]);

    useEffect(() => { load(); }, [load]);
    const sources = data?.sources || [];
    const runs = data?.runs || [];
    const notes = data?.notes || [];
    const reports = data?.reports || [];
    const roadmap = data?.roadmap || [];
    const outline = data?.report_outline || [];
    const counts = data?.counts || {};
    const correlation = data?.correlation || {};
    const topTypes = correlation.top_types || [];

    async function saveSource() {
      setSaving(true);
      setError("");
      try {
        await SDK.fetchJSON("/api/plugins/spook-shack/sources", {
          method: "POST",
          headers: { "X-Spook-Shack-Role": role, "Content-Type": "application/json" },
          body: JSON.stringify(form),
        });
        setForm((prev) => ({ ...prev, source_key: "", display_name: "", rate_limit_note: "", policy_note: "", credential_hint: "", enabled: true }));
        await load();
      } catch (err) {
        setError(parseError(err));
      } finally {
        setSaving(false);
      }
    }

    async function queueRun(sourceKey) {
      setQueued(sourceKey);
      setSaving(true);
      setError("");
      try {
        await SDK.fetchJSON(`/api/plugins/spook-shack/sources/${encodeURIComponent(sourceKey)}/queue`, {
          method: "POST",
          headers: { "X-Spook-Shack-Role": role, "Content-Type": "application/json" },
          body: JSON.stringify({ reason: "dashboard action", requested_by: role, mode: "queued" }),
        });
        await load();
      } catch (err) {
        setError(parseError(err));
      } finally {
        setSaving(false);
        setQueued("");
      }
    }

    async function draftReport() {
      setSaving(true);
      setError("");
      try {
        await SDK.fetchJSON("/api/plugins/spook-shack/reports/draft", {
          method: "POST",
          headers: { "X-Spook-Shack-Role": role, "Content-Type": "application/json" },
          body: JSON.stringify({ cadence, created_by: role }),
        });
        await load();
      } catch (err) {
        setError(parseError(err));
      } finally {
        setSaving(false);
      }
    }

    return h("div", { className: "spook-shack-page" },
      h(Card, null,
        h(CardContent, { className: "spook-shack-hero" },
          h("div", null,
            h("div", { className: "spook-shack-kicker" }, "Threat intelligence MVP"),
            h(CardTitle, { className: "spook-shack-title" }, "Spook Shack"),
            h("p", { className: "spook-shack-copy" }, "Source registry, queued ingestion scaffolding, analyst notes, and draft CTI reports — ready to grow safely as new feeds come online."),
            h("div", { className: "spook-shack-pillrow" },
              h(Badge, { variant: role === "admin" ? "success" : "secondary" }, `role: ${role}`),
              h(Badge, { variant: "secondary" }, `${sources.length} sources`),
              h(Badge, { variant: "secondary" }, `${reports.length} reports`),
            ),
          ),
          h("div", { className: "spook-shack-hero-actions" },
            h("label", { className: "spook-shack-role" }, h("span", null, "Role"), h("select", { value: role, onChange: (e) => setRole(e.target.value) }, h("option", { value: "admin" }, "admin"), h("option", { value: "analyst" }, "analyst"))),
            h(Button, { onClick: load, disabled: loading || saving }, loading ? "Refreshing…" : "Refresh"),
            h(Button, { onClick: draftReport, disabled: saving }, `Draft ${cadence} report`),
            h("label", { className: "spook-shack-role" }, h("span", null, "Cadence"), h("select", { value: cadence, onChange: (e) => setCadence(e.target.value) }, h("option", { value: "weekly" }, "weekly"), h("option", { value: "monthly" }, "monthly"), h("option", { value: "quarterly" }, "quarterly"), h("option", { value: "annual" }, "annual"))),
          ),
        ),
      ),
      error ? h(Card, { className: "spook-shack-error" }, h(CardContent, null, error)) : null,
      h("section", null,
        h("div", { className: "spook-shack-section-head" }, h("h2", null, "Roadmap"), h("p", null, "The initial MVP slice is wired; the next steps are queued in the data model.")),
        h("div", { className: "spook-shack-roadmap" }, roadmap.map((item) => h(Card, { key: item.id }, h(CardHeader, null, h(CardTitle, null, item.title)), h(CardContent, null, h("p", null, item.summary))))),
      ),
      h("section", null,
        h("div", { className: "spook-shack-metrics" },
          [["Sources", counts.sources], ["Enabled", counts.enabled_sources], ["Queued runs", counts.queued_runs], ["Observables", counts.observables], ["Reports", counts.reports]].map(([label, value]) => h(Card, { key: label }, h(CardContent, null, h("div", { className: "spook-shack-metric-label" }, label), h("div", { className: "spook-shack-metric-value" }, String(value ?? 0)), h("div", { className: "spook-shack-metric-hint" }, "SQLite-backed MVP data"))))
        ),
      ),
      h("section", null,
        h("div", { className: "spook-shack-section-head" }, h("h2", null, "Source registry"), h("p", null, "Admin can add or update sources; analysts can still review the catalog and queue status.")),
        h(Card, null,
          h(CardContent, null,
            h("div", { className: "spook-shack-form" },
              [
                ["Source key", "source_key"], ["Display name", "display_name"], ["Source type", "source_type"], ["Schedule", "schedule"], ["Rate-limit note", "rate_limit_note"], ["Policy note", "policy_note"], ["Credential hint", "credential_hint"],
              ].map(([label, key]) => h("label", { key }, h("span", null, label), h(Input, { value: form[key], onChange: (e) => setForm((prev) => ({ ...prev, [key]: e.target.value })) }))),
              h("label", { className: "spook-shack-checkbox" }, h("input", { type: "checkbox", checked: form.enabled, onChange: (e) => setForm((prev) => ({ ...prev, enabled: e.target.checked })) }), h("span", null, "Enabled")),
              h("div", { className: "spook-shack-form-actions" }, h(Button, { onClick: saveSource, disabled: saving }, saving ? "Saving…" : "Save source")),
            ),
          ),
        ),
        h("div", { className: "spook-shack-source-grid" }, sources.map((source) => h(Card, { key: source.source_key }, h(CardHeader, null, h("div", { className: "spook-shack-source-head" }, h("div", null, h(CardTitle, null, source.display_name), h("div", { className: "spook-shack-source-sub" }, source.source_key)), h(Badge, { variant: source.enabled ? "success" : "secondary" }, source.enabled ? "enabled" : "disabled"))), h(CardContent, null, h("div", { className: "spook-shack-dl" }, h("div", null, h("dt", null, "Type"), h("dd", null, source.source_type)), h("div", null, h("dt", null, "Mode"), h("dd", null, source.ingestion_mode)), h("div", null, h("dt", null, "Schedule"), h("dd", null, source.schedule)), h("div", null, h("dt", null, "Last run"), h("dd", null, source.last_run_status || "none"))), h("p", { className: "spook-shack-text" }, source.rate_limit_note), h("p", { className: "spook-shack-text" }, source.policy_note), h("div", { className: "spook-shack-pillrow" }, h(Badge, { variant: "secondary" }, source.credential_hint || "no secret"), h(Badge, { variant: source.has_credentials ? "success" : "secondary" }, source.has_credentials ? "credentials stored" : "no credentials")), h("div", { className: "spook-shack-card-actions" }, h(Button, { onClick: () => queueRun(source.source_key), disabled: role !== "admin" || saving || queued === source.source_key }, queued === source.source_key ? "Queueing…" : "Queue run"))))))
      ),
      h("section", null,
        h("div", { className: "spook-shack-section-head" }, h("h2", null, "Correlation readiness"), h("p", null, "The schema already stores normalized observables and cross-source pivots.")),
        h("div", { className: "spook-shack-correlation" },
          h(Card, null, h(CardHeader, null, h(CardTitle, null, "Top observable types")), h(CardContent, null, topTypes.length ? topTypes.map((row) => h("div", { key: `${row.observable_type}-${row.total}`, className: "spook-shack-row" }, h("strong", null, row.observable_type), h("span", null, `${row.total} items · ${row.source_count} sources`))) : h("p", { className: "spook-shack-muted" }, "No observables yet — ingest a source to start building pivots."))),
          h(Card, null, h(CardHeader, null, h(CardTitle, null, "Report template")), h(CardContent, null, h("ol", { className: "spook-shack-outline" }, outline.map((item) => h("li", { key: item }, item))))),
        ),
      ),
      h("section", null,
        h("div", { className: "spook-shack-section-head" }, h("h2", null, "Recent activity"), h("p", null, "Queued runs, notes, and report drafts are all stored in SQLite.")),
        h("div", { className: "spook-shack-activity" },
          h(Card, null, h(CardHeader, null, h(CardTitle, null, "Recent runs")), h(CardContent, null, runs.length ? runs.slice(0, 5).map((run) => h("div", { key: run.id, className: "spook-shack-row" }, h("strong", null, run.source_key), h("span", null, `${run.status} · ${run.mode}`))) : h("p", { className: "spook-shack-muted" }, "No ingestion runs yet."))),
          h(Card, null, h(CardHeader, null, h(CardTitle, null, "Recent notes")), h(CardContent, null, notes.length ? notes.slice(0, 5).map((note) => h("div", { key: note.id, className: "spook-shack-row" }, h("strong", null, note.verdict.replace(/_/g, " ")), h("span", null, `${note.target_type}:${note.target_id}`))) : h("p", { className: "spook-shack-muted" }, "No analyst notes yet."))),
          h(Card, null, h(CardHeader, null, h(CardTitle, null, "Recent report drafts")), h(CardContent, null, reports.length ? reports.slice(0, 5).map((report) => h("div", { key: report.id, className: "spook-shack-row" }, h("strong", null, report.cadence), h("span", null, report.title))) : h("p", { className: "spook-shack-muted" }, "No report drafts yet."))),
        ),
      ),
    );
  }

  window.__HERMES_PLUGINS__.register("spook-shack", App);
})();
