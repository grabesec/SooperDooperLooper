// SDL page: pick systems from the inventory, roll them over, watch each
// system's result, and review the audit log. Everything goes through the same HTTP API the
// CLI uses; this page holds no state of its own beyond the tab's token.
"use strict";

const TOKEN_KEY = "sdl.token";
const STATUS_LABELS = {
  succeeded: "Succeeded",
  checked: "Checked",
  failed: "Failed (unchanged)",
  rolled_back: "Rolled back",
  needs_attention: "Needs attention",
  pending: "Pending",
  running: "Running",
  partial: "Partial",
};

const state = {
  me: null,
  systems: [],
  sources: [],
  selected: new Set(),
  editing: null,
  pollTimer: null,
};

const $ = (id) => document.getElementById(id);

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key in node) node[key] = value;
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function token() {
  try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
}

function setToken(value) {
  try {
    if (value) sessionStorage.setItem(TOKEN_KEY, value);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch { /* storage unavailable: the token lives only in this page */ }
  state.token = value;
}

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(method, path, body) {
  const headers = { Authorization: `Bearer ${state.token || token() || ""}` };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401) {
    signOut("Your token was not accepted.");
    throw new ApiError(401, "not signed in");
  }
  if (response.status === 204) return null;
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    let detail = data && data.detail;
    if (Array.isArray(detail)) detail = detail.map((d) => `${(d.loc || []).slice(1).join(".")}: ${d.msg}`).join("; ");
    throw new ApiError(response.status, detail || `HTTP ${response.status}`);
  }
  return data;
}

const can = (permission) => Boolean(state.me && state.me.permissions.includes(permission));

// -- sign in -----------------------------------------------------------------

async function signIn(value) {
  setToken(value);
  try {
    state.me = await api("GET", "/api/v1/me");
  } catch (err) {
    if (err.status !== 401) signOut(err.message);
    return;
  }
  $("signin").hidden = true;
  $("app").hidden = false;
  $("who").hidden = false;
  const roles = state.me.actor.roles.join(", ");
  $("who-name").textContent = `${state.me.actor.display_name || state.me.actor.id} (${roles})`;
  $("history").hidden = !can("rollover:read");
  $("log").hidden = !can("audit:read");
  await loadSystems();
  if (can("rollover:read")) await loadRuns();
  updateRunButton();
  if (can("audit:read")) await loadLog();
}

function signOut(message) {
  setToken(null);
  state.me = null;
  state.selected.clear();
  clearTimeout(state.pollTimer);
  $("app").hidden = true;
  $("who").hidden = true;
  $("signin").hidden = false;
  $("signin-error").textContent = message || "";
  $("token").value = "";
}

// -- systems -------------------------------------------------------------------

async function loadSystems() {
  const inventory = await api("GET", "/api/v1/systems");
  state.systems = inventory.systems;
  state.sources = inventory.sources;
  const names = new Set(state.systems.map((s) => s.name));
  for (const name of [...state.selected]) if (!names.has(name)) state.selected.delete(name);
  fillFilters();
  renderNotes();
  renderSystems();
  const writable = state.sources.some((s) => s.writable);
  $("add-system").hidden = !(writable && can("inventory:write"));
}

function fillFilters() {
  const fill = (select, values, label) => {
    const current = select.value;
    select.replaceChildren(el("option", { value: "" }, label), ...values.map((v) => el("option", { value: v }, v)));
    select.value = values.includes(current) ? current : "";
  };
  const groups = [...new Set(state.systems.flatMap((s) => s.groups))].sort();
  fill($("group-filter"), groups, "All groups");
  fill($("source-filter"), state.sources.map((s) => s.id), "All inventories");
}

function renderNotes() {
  const notes = [];
  for (const source of state.sources) {
    if (!source.ok) notes.push(`Inventory ${source.id} is unavailable: ${source.error}`);
    if (source.skipped.length) {
      notes.push(`Inventory ${source.id}: ${source.skipped.join(", ")} not listed, an earlier inventory has the same name.`);
    }
  }
  $("inventory-notes").replaceChildren(...notes.map((n) => el("p", { class: "note" }, n)));
}

function visibleSystems() {
  const words = $("filter").value.toLowerCase().split(/\s+/).filter(Boolean);
  const group = $("group-filter").value;
  const source = $("source-filter").value;
  return state.systems.filter((s) => {
    if (group && !s.groups.includes(group)) return false;
    if (source && s.source !== source) return false;
    const hay = [s.name, s.hostname, s.fqdn, s.host, ...s.addresses, ...s.groups, s.description]
      .filter(Boolean).join(" ").toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}

function renderSystems() {
  const rows = visibleSystems().map((s) => {
    const selected = state.selected.has(s.name);
    const box = el("input", { type: "checkbox", checked: selected, ariaLabel: `Select ${s.name}` });
    box.addEventListener("change", () => toggle(s.name, box.checked));
    const source = state.sources.find((x) => x.id === s.source);
    const buttons = [];
    if (can("audit:read")) {
      const log = el("button", { type: "button", class: "secondary" }, "Log");
      log.addEventListener("click", (e) => { e.stopPropagation(); showSystemLog(s.name); });
      buttons.push(log);
    }
    if (source && source.writable && can("inventory:write")) {
      const edit = el("button", { type: "button", class: "secondary" }, "Edit");
      edit.addEventListener("click", (e) => { e.stopPropagation(); openSystemDialog(s); });
      const del = el("button", { type: "button", class: "danger" }, "Delete");
      del.addEventListener("click", (e) => { e.stopPropagation(); deleteSystem(s); });
      buttons.push(edit, del);
    }
    const actions = buttons.length ? el("span", { class: "tools" }, buttons) : null;
    const sa = s.service_account ? `${s.service_account.username}` : el("span", { class: "muted" }, "module default");
    const row = el("tr", { class: `selectable${selected ? " selected" : ""}` },
      el("td", { class: "check" }, box),
      el("td", {}, el("strong", {}, s.name), s.description ? el("div", { class: "muted" }, s.description) : null),
      el("td", {}, s.hostname || ""),
      el("td", { class: "mono" }, s.fqdn || ""),
      el("td", { class: "mono" }, s.addresses.join(", ")),
      el("td", {}, s.account),
      el("td", {}, sa),
      el("td", {}, s.groups.map((g) => el("span", { class: "chip" }, g))),
      el("td", {}, s.source || ""),
      el("td", {}, actions),
    );
    row.addEventListener("click", (e) => {
      if (e.target.closest("input, button")) return;
      toggle(s.name, !state.selected.has(s.name));
    });
    return row;
  });
  $("systems").tBodies[0].replaceChildren(...rows);
  $("systems-empty").hidden = rows.length > 0;
  const shown = visibleSystems();
  const all = $("select-all");
  all.checked = shown.length > 0 && shown.every((s) => state.selected.has(s.name));
  all.indeterminate = !all.checked && shown.some((s) => state.selected.has(s.name));
  updateRunButton();
}

function toggle(name, on) {
  if (on) state.selected.add(name); else state.selected.delete(name);
  renderSystems();
}

function updateRunButton() {
  const n = state.selected.size;
  $("selected-count").textContent = `${n} system${n === 1 ? "" : "s"} selected`;
  const dry = $("dry-run").checked;
  $("run").textContent = dry ? `Check ${n} system${n === 1 ? "" : "s"}` : `Roll over ${n} system${n === 1 ? "" : "s"}`;
  $("run").disabled = !(n > 0 && $("reason").value.trim() && can("rollover:run"));
}

// -- add / edit systems ----------------------------------------------------------

const split = (text) => text.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

function openSystemDialog(system) {
  state.editing = system || null;
  const writable = state.sources.filter((s) => s.writable);
  $("f-inventory").replaceChildren(...writable.map((s) => el("option", { value: s.id }, s.id)));
  $("system-dialog-title").textContent = system ? `Edit ${system.name}` : "Add system";
  const s = system || {};
  const sa = s.service_account || {};
  $("f-inventory").value = s.source || (writable[0] && writable[0].id) || "";
  $("f-inventory").disabled = Boolean(system);
  $("f-name").value = s.name || "";
  $("f-name").readOnly = Boolean(system);
  $("f-hostname").value = s.hostname || "";
  $("f-fqdn").value = s.fqdn || "";
  $("f-addresses").value = (s.addresses || []).join(", ");
  const derived = s.fqdn || (s.addresses && s.addresses[0]) || s.hostname;
  $("f-host").value = s.host && s.host !== derived ? s.host : "";
  $("f-port").value = s.port || 22;
  $("f-account").value = s.account || "root";
  $("f-secret-path").value = s.secret_path || "";
  $("f-module").value = s.module || "";
  $("f-sa-user").value = sa.username || "";
  $("f-sa-path").value = sa.credential_path || "";
  $("f-sa-type").value = sa.credential_type || "ssh_key";
  $("f-groups").value = (s.groups || []).join(", ");
  $("f-description").value = s.description || "";
  $("system-error").textContent = "";
  $("system-dialog").showModal();
}

async function saveSystem(event) {
  event.preventDefault();
  const value = (id) => $(id).value.trim();
  const body = {
    name: value("f-name"),
    hostname: value("f-hostname") || null,
    fqdn: value("f-fqdn") || null,
    addresses: split(value("f-addresses")),
    host: value("f-host"),
    port: Number(value("f-port") || 22),
    account: value("f-account") || "root",
    secret_path: value("f-secret-path"),
    module: value("f-module") || null,
    groups: split(value("f-groups")),
    description: value("f-description") || null,
    service_account: null,
  };
  if (state.editing) {
    body.secrets = state.editing.secrets;
    body.options = state.editing.options;
  }
  if (value("f-sa-user") || value("f-sa-path")) {
    body.service_account = {
      username: value("f-sa-user"),
      credential_path: value("f-sa-path"),
      credential_type: value("f-sa-type"),
      secrets: state.editing && state.editing.service_account ? state.editing.service_account.secrets : null,
    };
  }
  const inventory = value("f-inventory");
  try {
    await api("PUT", `/api/v1/inventory/${encodeURIComponent(inventory)}/systems/${encodeURIComponent(body.name)}`, body);
  } catch (err) {
    $("system-error").textContent = err.message;
    return;
  }
  $("system-dialog").close();
  await loadSystems();
}

async function deleteSystem(system) {
  if (!confirm(`Remove ${system.name} from inventory ${system.source}? Its credentials in the secrets module are not touched.`)) return;
  try {
    await api("DELETE", `/api/v1/inventory/${encodeURIComponent(system.source)}/systems/${encodeURIComponent(system.name)}`);
  } catch (err) {
    alert(err.message);
  }
  state.selected.delete(system.name);
  await loadSystems();
}

// -- runs ---------------------------------------------------------------------------

async function startRun(event) {
  event.preventDefault();
  const names = [...state.selected];
  const dryRun = $("dry-run").checked;
  if (!dryRun && !confirm(`Roll over the credential on ${names.length} system(s) now?\n\n${names.join(", ")}`)) return;
  $("run-error").textContent = "";
  $("run").disabled = true;
  try {
    const run = await api("POST", "/api/v1/rollovers", {
      targets: names, reason: $("reason").value.trim(), dry_run: dryRun,
    });
    showRun(run);
  } catch (err) {
    $("run-error").textContent = err.message;
  } finally {
    updateRunButton();
  }
}

function showRun(run) {
  clearTimeout(state.pollTimer);
  $("result").hidden = false;
  $("result-title").textContent = `${run.dry_run ? "Dry run" : "Rollover"} ${run.id.slice(0, 8)}`;
  const badge = $("result-status");
  badge.textContent = STATUS_LABELS[run.status] || run.status;
  badge.className = `badge s-${run.status}`;
  $("result-meta").textContent = `Requested by ${run.requested_by.id} at ${new Date(run.created_at).toLocaleString()}: ${run.reason}`
    + (run.finished_at ? ` · finished ${new Date(run.finished_at).toLocaleTimeString()}` : "");
  const rows = run.results.map((r) => el("tr", {},
    el("td", {}, el("strong", {}, r.target), r.source ? el("div", { class: "muted" }, r.source) : null),
    el("td", { class: "mono" }, r.host),
    el("td", {}, r.account),
    el("td", {}, el("span", { class: `badge s-${r.status}` }, STATUS_LABELS[r.status] || r.status)),
    el("td", {}, r.secret_version || "–"),
    el("td", {},
      r.message || "",
      r.steps.length ? el("details", {},
        el("summary", {}, `${r.steps.length} steps`),
        el("ol", {}, r.steps.map((s) => el("li", {},
          `${new Date(s.ts).toLocaleTimeString()} ${s.name}: ${s.outcome}${s.message ? ` (${s.message})` : ""}`)))) : null,
    ),
  ));
  $("results").tBodies[0].replaceChildren(...rows);
  if (run.status === "pending" || run.status === "running") {
    state.pollTimer = setTimeout(async () => {
      try { showRun(await api("GET", `/api/v1/rollovers/${run.id}`)); } catch { /* shown on next action */ }
    }, 1500);
  } else {
    if (can("rollover:read")) loadRuns();
    if (can("audit:read")) loadLog();
  }
}

async function loadRuns() {
  const runs = await api("GET", "/api/v1/rollovers");
  const items = runs.slice(0, 20).map((run) => {
    const open = el("button", { type: "button", class: "secondary" }, "Show");
    open.addEventListener("click", async () => showRun(await api("GET", `/api/v1/rollovers/${run.id}`)));
    const counts = {};
    for (const r of run.results) counts[r.status] = (counts[r.status] || 0) + 1;
    const summary = Object.entries(counts).map(([s, n]) => `${n} ${(STATUS_LABELS[s] || s).toLowerCase()}`).join(", ");
    return el("li", {}, open,
      el("span", { class: `badge s-${run.status}` }, STATUS_LABELS[run.status] || run.status), " ",
      `${new Date(run.created_at).toLocaleString()} · ${run.requested_by.id} · ${summary} · ${run.reason}`);
  });
  $("runs").replaceChildren(...(items.length ? items : [el("li", { class: "muted" }, "No runs yet.")]));
}

// -- log ----------------------------------------------------------------------------

const OUTCOME_LABELS = { success: "Success", failure: "Failure", denied: "Denied", started: "Started", info: "Info" };

async function loadLogFacets() {
  const facets = await api("GET", "/api/v1/audit/facets");
  const fill = (select, values, label, describe) => {
    const current = select.value;
    select.replaceChildren(el("option", { value: "" }, label),
      ...values.map((v) => el("option", { value: v }, describe ? describe(v) : v)));
    select.value = values.includes(current) ? current : "";
  };
  const sorted = (counts) => Object.keys(counts).sort();
  // Offer every action and each of its prefixes: "rollover" covers "rollover.target.change".
  const actions = new Set();
  for (const action of Object.keys(facets.actions)) {
    const parts = action.split(".");
    for (let i = 1; i <= parts.length; i++) actions.add(parts.slice(0, i).join("."));
  }
  const exact = new Set(Object.keys(facets.actions));
  fill($("log-action"), [...actions].sort(), "All actions", (a) => (exact.has(a) ? a : `${a}.* (all)`));
  fill($("log-target"), sorted(facets.targets), "All systems");
  fill($("log-actor"), sorted(facets.actors), "Everyone");
  fill($("log-module"), sorted(facets.modules), "All modules");
}

function logParams() {
  const params = new URLSearchParams({ order: "newest", limit: $("log-limit").value });
  const add = (key, id) => { const v = $(id).value.trim(); if (v) params.append(key, v); };
  add("target", "log-target");
  add("action", "log-action");
  add("outcome", "log-outcome");
  add("actor", "log-actor");
  add("module", "log-module");
  add("q", "log-q");
  // datetime-local is in the browser's time zone; the API takes ISO 8601 with a zone.
  for (const [key, id] of [["since", "log-since"], ["until", "log-until"]]) {
    const v = $(id).value;
    if (v) params.append(key, new Date(v).toISOString());
  }
  return params;
}

function eventRow(e) {
  let who = `${e.actor.type}:${e.actor.id}`;
  if (e.initiated_by) who += ` for ${e.initiated_by.id}`;
  const details = Object.keys(e.details || {}).length
    ? el("details", {}, el("summary", {}, "details"), el("pre", {}, JSON.stringify(e.details, null, 2)))
    : null;
  return el("tr", {},
    el("td", { class: "nowrap mono", title: e.ts }, new Date(e.ts).toLocaleString()),
    el("td", {}, el("span", { class: `badge o-${e.outcome}` }, OUTCOME_LABELS[e.outcome] || e.outcome)),
    el("td", { class: "mono" }, e.action),
    el("td", {}, e.target || ""),
    el("td", {}, e.module || ""),
    el("td", {}, who),
    el("td", {}, e.message || "", e.run_id ? el("div", { class: "muted mono" }, `run ${e.run_id.slice(0, 8)}`) : null, details),
  );
}

async function loadLog() {
  $("log-error").textContent = "";
  try {
    await loadLogFacets();
    const limit = Number($("log-limit").value);
    const events = await api("GET", `/api/v1/audit?${logParams()}`);
    $("events").tBodies[0].replaceChildren(...events.map(eventRow));
    $("log-summary").textContent = events.length
      ? `${events.length} event${events.length === 1 ? "" : "s"}, newest first${events.length >= limit ? ` (the latest ${limit}; narrow the dates to see older ones)` : ""}.`
      : "No events match.";
  } catch (err) {
    $("log-error").textContent = err.message;
  }
  loadForwarders();
}

async function loadForwarders() {
  let forwarders = [];
  try { forwarders = await api("GET", "/api/v1/forwarders"); } catch { /* shown as nothing */ }
  $("forwarders").replaceChildren(...forwarders.map((f) => el("span", { class: "chip", title: f.last_error || "" },
    `Forwarding to ${f.id}: `,
    el("span", { class: f.ok ? "ok-text" : "bad-text" }, f.ok ? "ok" : "retrying"),
    ` · ${f.sent} sent · ${f.queued} queued${f.dropped ? ` · ${f.dropped} dropped` : ""}`)));
}

async function verifyLog() {
  $("log-integrity").textContent = "Checking…";
  try {
    const result = await api("GET", "/api/v1/audit/verify");
    $("log-integrity").textContent = result.detail;
    $("log-integrity").className = result.ok ? "ok-text" : "bad-text";
  } catch (err) {
    $("log-integrity").textContent = err.message;
    $("log-integrity").className = "bad-text";
  }
}

function resetLogFilters() {
  for (const id of ["log-target", "log-action", "log-outcome", "log-actor", "log-module", "log-since", "log-until", "log-q"]) $(id).value = "";
}

async function showSystemLog(name) {
  resetLogFilters();
  await loadLogFacets();
  if (![...$("log-target").options].some((o) => o.value === name)) {
    $("log-target").append(el("option", { value: name }, name));
  }
  $("log-target").value = name;
  await loadLog();
  $("log").scrollIntoView({ behavior: "smooth" });
}

// -- wiring -------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  $("signin-form").addEventListener("submit", (e) => { e.preventDefault(); signIn($("token").value.trim()); });
  $("sign-out").addEventListener("click", () => signOut());
  for (const id of ["filter", "group-filter", "source-filter"]) $(id).addEventListener("input", renderSystems);
  $("select-all").addEventListener("change", (e) => {
    for (const s of visibleSystems()) {
      if (e.target.checked) state.selected.add(s.name); else state.selected.delete(s.name);
    }
    renderSystems();
  });
  $("refresh").addEventListener("click", async () => {
    try {
      await api("POST", "/api/v1/inventory/refresh");
      await loadSystems();
    } catch (err) { alert(err.message); }
  });
  $("add-system").addEventListener("click", () => openSystemDialog(null));
  $("system-form").addEventListener("submit", saveSystem);
  $("system-cancel").addEventListener("click", () => $("system-dialog").close());
  $("reason").addEventListener("input", updateRunButton);
  $("dry-run").addEventListener("change", updateRunButton);
  $("run-form").addEventListener("submit", startRun);
  $("log-form").addEventListener("submit", (e) => { e.preventDefault(); loadLog(); });
  $("log-reset").addEventListener("click", () => { resetLogFilters(); loadLog(); });
  $("log-verify").addEventListener("click", verifyLog);

  const saved = token();
  if (saved) signIn(saved);
  else signOut();
});
