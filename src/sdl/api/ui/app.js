// SDL page: sign in, pick systems from the inventory, roll them over, watch each
// system's result, review the audit log, and manage users. Everything goes through the same
// HTTP API the CLI uses; this page holds no state of its own beyond the tab's session token.
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
  providers: [],
  roles: [],
  users: [],
  idps: [],
  editingUser: null,
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
    signOut("Your sign-in has ended. Please sign in again.");
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

async function loadProviders() {
  try {
    const response = await fetch("/api/v1/auth/providers");
    state.providers = response.ok ? await response.json() : [];
  } catch { state.providers = []; }
  const passwordProviders = state.providers.filter((p) => p.login === "password");
  $("provider").replaceChildren(...passwordProviders.map((p) => el("option", { value: p.id }, p.name)));
  $("provider-row").hidden = passwordProviders.length < 2;
  $("signin-form").hidden = passwordProviders.length === 0;
  $("sso-buttons").replaceChildren(...state.providers.filter((p) => p.login === "redirect").map((p) => {
    const button = el("button", { type: "button", class: "secondary" }, `Sign in with ${p.name}`);
    button.addEventListener("click", () => {
      window.location.href = `/api/v1/auth/sso/${encodeURIComponent(p.id)}/start?return_to=ui`;
    });
    return button;
  }));
}

async function passwordSignIn(event) {
  event.preventDefault();
  $("signin-error").textContent = "";
  const body = {
    username: $("username").value.trim(),
    password: $("password").value,
    provider: $("provider").value || null,
    code: $("code").value.replace(/\s/g, "") || null,
  };
  const response = await fetch("/api/v1/auth/login", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = data && data.detail;
    if (detail && detail.mfa_required) {
      $("code-row").hidden = false;
      $("code").focus();
      $("signin-error").textContent = detail.message;
    } else {
      $("signin-error").textContent = (detail && (detail.message || detail)) || `HTTP ${response.status}`;
    }
    return;
  }
  $("password").value = "";
  $("code").value = "";
  $("code-row").hidden = true;
  await signIn(data.token);
}

async function finishSso() {
  // A single sign-on comes back as /ui/#sso=<one-time code> (or #sso_error=, #cli_code=).
  const params = new URLSearchParams(window.location.hash.slice(1));
  if (![...params.keys()].length) return false;
  history.replaceState(null, "", window.location.pathname);
  if (params.get("sso_error")) {
    const ssoErrors = {
      state_mismatch: "Single sign-on was not started from this browser. Please try again.",
      unavailable: "The sign-in service is unavailable. Please try again later.",
    };
    signOut(ssoErrors[params.get("sso_error")] || "Single sign-on failed.");
    return true;
  }
  if (params.get("cli_code")) {
    $("signin").hidden = true;
    $("cli-code").hidden = false;
    $("cli-code-value").value = params.get("cli_code");
    $("cli-code-value").select();
    return true;
  }
  if (params.get("sso")) {
    const response = await fetch("/api/v1/auth/sso/exchange", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: params.get("sso") }),
    });
    const data = await response.json().catch(() => null);
    if (!response.ok) signOut((data && data.detail) || "Sign-in failed.");
    else await signIn(data.token);
    return true;
  }
  return false;
}

async function signIn(value) {
  setToken(value);
  try {
    state.me = await api("GET", "/api/v1/me");
  } catch (err) {
    if (err.status !== 401) signOut(err.message);
    return;
  }
  $("signin").hidden = true;
  $("who").hidden = false;
  const roles = state.me.pending.length ? "setup needed" : state.me.actor.roles.join(", ") || "no role";
  $("who-name").textContent = `${state.me.actor.display_name || state.me.actor.id} (${roles})`;
  $("my-account").hidden = !state.me.signed_in_with || state.me.pending.length > 0;
  if (state.me.pending.length) {
    showPending();
    return;
  }
  $("pending").hidden = true;
  $("app").hidden = false;
  $("history").hidden = !can("rollover:read");
  $("log").hidden = !can("audit:read");
  $("users").hidden = !can("users:read");
  await loadSystems();
  if (can("rollover:read")) await loadRuns();
  updateRunButton();
  if (can("audit:read")) await loadLog();
  if (can("users:read")) await loadUsers();
}

async function signOut(message) {
  const current = state.token || token();
  if (current && current.startsWith("sdls_") && state.me) {
    fetch("/api/v1/auth/logout", { method: "POST", headers: { Authorization: `Bearer ${current}` } }).catch(() => {});
  }
  setToken(null);
  state.me = null;
  state.selected.clear();
  clearTimeout(state.pollTimer);
  $("app").hidden = true;
  $("who").hidden = true;
  $("pending").hidden = true;
  $("cli-code").hidden = true;
  $("signin").hidden = false;
  $("signin-error").textContent = message || "";
  $("token").value = "";
  $("password").value = "";
}

// -- your own account: forced password change, authenticator app ---------------

function showPending() {
  $("app").hidden = true;
  $("pending").hidden = false;
  $("pending-error").textContent = "";
  const pending = state.me.pending;
  $("pending-password").hidden = !pending.includes("password_change");
  const mfa = !pending.includes("password_change") && pending.includes("mfa_enrollment");
  $("pending-mfa").hidden = !mfa;
  if (mfa) startTotp($("pending-mfa").querySelector(".mfa-box"), $("pending-error"));
}

function checkNewPassword(newId, againId) {
  if ($(newId).value !== $(againId).value) throw new Error("The new passwords do not match.");
}

async function changePassword(currentId, newId, againId) {
  checkNewPassword(newId, againId);
  await api("POST", "/api/v1/me/password", {
    current_password: $(currentId).value, new_password: $(newId).value,
  });
  for (const id of [currentId, newId, againId]) $(id).value = "";
}

async function startTotp(box, errorNode) {
  box.replaceChildren(el("p", { class: "muted" }, "Preparing…"));
  let enrollment;
  try {
    enrollment = await api("POST", "/api/v1/me/mfa/totp");
  } catch (err) {
    box.replaceChildren();
    errorNode.textContent = err.message;
    return;
  }
  const grouped = enrollment.secret.match(/.{1,4}/g).join(" ");
  const code = el("input", { inputmode: "numeric", autocomplete: "one-time-code", maxLength: 8, required: true });
  const confirmButton = el("button", { type: "button" }, "Confirm");
  confirmButton.addEventListener("click", async () => {
    errorNode.textContent = "";
    try {
      await api("POST", "/api/v1/me/mfa/totp/confirm", { code: code.value.replace(/\s/g, "") });
    } catch (err) {
      errorNode.textContent = err.message;
      return;
    }
    if ($("account-dialog").open) $("account-dialog").close();
    await signIn(state.token || token());
  });
  box.replaceChildren(
    el("ol", {},
      el("li", {}, "In the app, add an account by entering this key (time based):",
        el("div", { class: "secret mono" }, grouped)),
      el("li", {}, "On a phone, you can instead open ", el("a", { href: enrollment.uri }, "this link"), "."),
      el("li", {}, "Enter the code the app shows:")),
    el("div", { class: "inline-form" }, code, confirmButton),
  );
  code.focus();
}

function openAccount() {
  const me = state.me;
  $("account-error").textContent = "";
  $("account-message").textContent = "";
  const how = { local: "an SDL password", superuser: "the superuser account" }[me.signed_in_with]
    || ((state.providers.find((p) => p.id === me.signed_in_with) || {}).name || me.signed_in_with);
  $("account-summary").textContent = `${me.actor.id}, signed in with ${how}`
    + (me.session_expires_at ? ` until ${new Date(me.session_expires_at).toLocaleString()}` : "")
    + `. Reaches ${describeAccess(me.access)}.`;
  $("account-password").hidden = !me.can_change_password;
  const box = $("account-mfa").querySelector(".mfa-box");
  $("account-mfa").hidden = me.signed_in_with === "superuser" && !me.mfa;
  if (me.mfa) {
    box.replaceChildren(el("p", {}, "An authenticator app is set up. If you lose it, ask an administrator to reset it."));
  } else if (me.signed_in_with === "superuser") {
    box.replaceChildren();
  } else {
    const start = el("button", { type: "button", class: "secondary" }, "Set up an authenticator app");
    start.addEventListener("click", () => startTotp(box, $("account-error")));
    box.replaceChildren(el("p", { class: "muted" }, "Not set up: sign-in only asks for your password."), start);
  }
  $("account-dialog").showModal();
}

function describeAccess(access) {
  if (!access || access.all_systems) return "every system";
  const parts = [...access.groups.map((g) => `group ${g}`), ...access.systems.map((s) => `system ${s}`)];
  return parts.length ? parts.join(", ") : "no systems";
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

// -- users ---------------------------------------------------------------------------

async function loadUsers() {
  $("users-error").textContent = "";
  try {
    const [users, roles, idps] = await Promise.all([
      api("GET", "/api/v1/users"),
      state.roles.length ? state.roles : api("GET", "/api/v1/roles"),
      api("GET", "/api/v1/idps"),
    ]);
    state.users = users;
    state.roles = roles;
    state.idps = idps;
  } catch (err) {
    $("users-error").textContent = err.message;
    return;
  }
  const manage = can("users:write") && (!state.me.access || state.me.access.all_systems);
  $("add-user").hidden = !manage;
  $("import-user").hidden = !(manage && state.idps.some((p) => p.can_search));
  renderUsers();
}

function renderUsers() {
  const words = $("user-filter").value.toLowerCase().split(/\s+/).filter(Boolean);
  const manage = !$("add-user").hidden;
  const providerName = (id) => (state.idps.find((p) => p.id === id) || {}).name || id;
  const shown = state.users.filter((u) => {
    const hay = [u.name, u.display_name, u.email, u.source, ...u.roles, ...u.access.groups, ...u.access.systems]
      .filter(Boolean).join(" ").toLowerCase();
    return words.every((w) => hay.includes(w));
  });
  const rows = shown.map((u) => {
    const buttons = [];
    if (manage) {
      const add = (label, cls, fn) => {
        const b = el("button", { type: "button", class: cls }, label);
        b.addEventListener("click", fn);
        buttons.push(b);
      };
      add("Edit", "secondary", () => openUserDialog(u));
      if (u.source === "local") add("Set password", "secondary", () => setUserPassword(u));
      if (u.mfa) add("Reset MFA", "secondary", () => userAction(u, "DELETE", "mfa", `Remove ${u.name}'s authenticator? They set up a new one at next sign-in.`));
      add("Unlock", "secondary", () => userAction(u, "POST", "unlock", null));
      add("Delete", "danger", () => userAction(u, "DELETE", "", `Remove ${u.name} from SDL?`));
    }
    let stateText = u.enabled ? "Enabled" : "Disabled";
    if (u.must_change_password) stateText += " · must change password";
    if (u.source === "local" && !u.has_password) stateText += " · no password yet";
    return el("tr", {},
      el("td", {}, el("strong", {}, u.name), u.display_name ? el("div", { class: "muted" }, u.display_name) : null),
      el("td", {}, u.source === "local" ? "SDL password" : providerName(u.source),
        u.external_groups.length ? el("div", { class: "muted" }, `groups: ${u.external_groups.join(", ")}`) : null),
      el("td", {}, el("span", { class: `badge ${u.enabled ? "s-succeeded" : "s-failed"}` }, stateText)),
      el("td", {}, u.roles.length ? u.roles.map((r) => el("span", { class: "chip" }, r)) : el("span", { class: "muted" }, "from directory groups")),
      el("td", {}, describeAccess(u.access)),
      el("td", {}, u.mfa ? "TOTP" : (u.source === "local" ? "none" : "provider")),
      el("td", { class: "nowrap" }, u.last_login ? new Date(u.last_login).toLocaleString() : "never"),
      el("td", {}, buttons.length ? el("span", { class: "tools" }, buttons) : null),
    );
  });
  $("user-table").tBodies[0].replaceChildren(...rows);
  $("users-empty").hidden = rows.length > 0;
}

function fillMultiSelect(select, values, chosen) {
  select.replaceChildren(...values.map((v) => el("option", { value: v, selected: chosen.includes(v) }, v)));
}

function openUserDialog(user) {
  state.editingUser = user || null;
  const u = user || { name: "", roles: ["operator"], access: { all_systems: false, groups: [], systems: [] }, enabled: true, source: "local" };
  $("user-dialog-title").textContent = user ? `Edit ${user.name}` : "Add user";
  $("u-name").value = u.name;
  $("u-name").readOnly = Boolean(user);
  $("u-display").value = u.display_name || "";
  $("u-email").value = u.email || "";
  $("u-password").value = "";
  $("u-password-row").hidden = Boolean(user);
  $("u-roles").replaceChildren(...state.roles.map((r) => el("label", { class: "inline", title: r.permissions.join(", ") },
    el("input", { type: "checkbox", value: r.name, checked: u.roles.includes(r.name) }), r.name)));
  const groups = [...new Set(state.systems.flatMap((s) => s.groups))].sort();
  const systems = state.systems.map((s) => s.name).sort();
  fillMultiSelect($("u-groups"), groups, u.access.groups);
  fillMultiSelect($("u-systems"), systems, u.access.systems);
  $("u-extra-groups").value = u.access.groups.filter((g) => !groups.includes(g)).join(", ");
  $("u-extra-systems").value = u.access.systems.filter((s) => !systems.includes(s)).join(", ");
  $("u-all").checked = u.access.all_systems;
  $("u-enabled").checked = u.enabled;
  $("u-source").textContent = u.source === "local" ? ""
    : `Signs in through ${u.source}. Roles, groups and systems set here are added to what the directory groups grant.`;
  $("user-error").textContent = "";
  $("user-dialog").showModal();
}

async function saveUser(event) {
  event.preventDefault();
  const picked = (id) => [...$(id).selectedOptions].map((o) => o.value);
  const access = {
    all_systems: $("u-all").checked,
    groups: [...new Set([...picked("u-groups"), ...split($("u-extra-groups").value)])],
    systems: [...new Set([...picked("u-systems"), ...split($("u-extra-systems").value)])],
  };
  const roles = [...$("u-roles").querySelectorAll("input:checked")].map((i) => i.value);
  const body = {
    display_name: $("u-display").value.trim() || null,
    email: $("u-email").value.trim() || null,
    roles, access, enabled: $("u-enabled").checked,
  };
  try {
    if (state.editingUser) {
      await api("PATCH", `/api/v1/users/${encodeURIComponent(state.editingUser.name)}`, body);
    } else {
      body.name = $("u-name").value.trim();
      if ($("u-password").value) body.password = $("u-password").value;
      await api("POST", "/api/v1/users", body);
    }
  } catch (err) {
    $("user-error").textContent = err.message;
    return;
  }
  $("user-dialog").close();
  await loadUsers();
}

async function userAction(user, method, suffix, question) {
  if (question && !confirm(question)) return;
  try {
    await api(method, `/api/v1/users/${encodeURIComponent(user.name)}${suffix ? `/${suffix}` : ""}`);
  } catch (err) {
    alert(err.message);
  }
  await loadUsers();
}

async function setUserPassword(user) {
  const password = prompt(`New password for ${user.name} (they must change it at next sign-in):`);
  if (!password) return;
  try {
    await api("POST", `/api/v1/users/${encodeURIComponent(user.name)}/password`, { password, temporary: true });
  } catch (err) {
    alert(err.message);
  }
  await loadUsers();
}

function openImportDialog() {
  const searchable = state.idps.filter((p) => p.can_search);
  $("i-provider").replaceChildren(...searchable.map((p) => el("option", { value: p.id }, p.name)));
  $("i-results").tBodies[0].replaceChildren();
  $("import-error").textContent = "";
  $("import-dialog").showModal();
}

async function searchDirectory() {
  $("import-error").textContent = "";
  const provider = $("i-provider").value;
  let found;
  try {
    found = await api("GET", `/api/v1/idps/${encodeURIComponent(provider)}/users?${new URLSearchParams({ q: $("i-query").value.trim() })}`);
  } catch (err) {
    $("import-error").textContent = err.message;
    return;
  }
  const known = new Set(state.users.map((u) => u.name));
  $("i-results").tBodies[0].replaceChildren(...found.map((u) => {
    let action = el("span", { class: "muted" }, "already in SDL");
    if (!known.has(u.username)) {
      action = el("button", { type: "button", class: "secondary" }, "Add");
      action.addEventListener("click", async () => {
        try {
          const user = await api("POST", `/api/v1/idps/${encodeURIComponent(provider)}/users`, { username: u.username });
          known.add(user.name);
          action.replaceWith(el("span", { class: "ok-text" }, "added"));
          await loadUsers();
        } catch (err) {
          $("import-error").textContent = err.message;
        }
      });
    }
    return el("tr", {}, el("td", {}, u.username), el("td", {}, u.display_name || ""), el("td", {}, u.email || ""),
      el("td", {}, u.groups.map((g) => el("span", { class: "chip" }, g))), el("td", {}, action));
  }));
}

// -- wiring -------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  $("signin-form").addEventListener("submit", passwordSignIn);
  $("token-form").addEventListener("submit", (e) => { e.preventDefault(); signIn($("token").value.trim()); });
  $("sign-out").addEventListener("click", () => signOut());
  $("my-account").addEventListener("click", openAccount);
  $("account-close").addEventListener("click", () => $("account-dialog").close());
  $("ap-save").addEventListener("click", async () => {
    $("account-error").textContent = "";
    try {
      await changePassword("ap-current", "ap-new", "ap-again");
      $("account-message").textContent = "Password changed. Your other sessions have ended.";
    } catch (err) { $("account-error").textContent = err.message; }
  });
  $("pending-password-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("pending-error").textContent = "";
    try {
      await changePassword("pp-current", "pp-new", "pp-again");
      await signIn(state.token || token());
    } catch (err) { $("pending-error").textContent = err.message; }
  });
  $("user-filter").addEventListener("input", renderUsers);
  $("add-user").addEventListener("click", () => openUserDialog(null));
  $("import-user").addEventListener("click", openImportDialog);
  $("user-form").addEventListener("submit", saveUser);
  $("user-cancel").addEventListener("click", () => $("user-dialog").close());
  $("i-search").addEventListener("click", searchDirectory);
  $("i-query").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); searchDirectory(); } });
  $("import-close").addEventListener("click", () => $("import-dialog").close());
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

  loadProviders().then(async () => {
    if (await finishSso()) return;
    const saved = token();
    if (saved) signIn(saved);
    else signOut();
  });
});
