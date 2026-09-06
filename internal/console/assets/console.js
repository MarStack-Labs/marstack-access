const REFRESH_MS = 5000;
const CONSOLE_HEADER = "X-Marac-Console";
const AUDIT_LIMIT = 200;

const RANK = { viewer: 1, operator: 2, admin: 3 };

const state = {
  view: "sessions",
  me: null,
  timer: null,
  targets: new Map(),
};

const $ = (id) => document.getElementById(id);

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === "class") {
      node.className = value;
    } else if (key.startsWith("on")) {
      node.addEventListener(key.slice(2), value);
    } else if (value !== null && value !== undefined) {
      node.setAttribute(key, value);
    }
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function toast(kind, title, detail) {
  const node = el("div", { class: "toast", "data-kind": kind },
    el("b", {}, title),
    detail ? el("span", {}, detail) : null);
  $("toasts").append(node);
  setTimeout(() => node.remove(), 7000);
}

async function api(method, path, body) {
  const options = {
    method,
    credentials: "same-origin",
    headers: { [CONSOLE_HEADER]: "1" },
  };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }

  let response;
  let text;
  try {
    response = await fetch(path, options);
    text = await response.text();
  } catch (failure) {
    return { ok: false, status: 0, data: null, detail: String(failure) };
  }

  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }

  if (response.status === 401 && path !== "/v1/console/session") {
    showSignIn("That session is over. Sign in again.");
    return { ok: false, status: 401, data, detail: "unauthenticated" };
  }

  const detail = data && data.error
    ? `${data.error.code}: ${data.error.message}`
    : text.slice(0, 200);

  return { ok: response.ok, status: response.status, data, detail };
}

function forget() {
  state.me = null;
  state.targets = new Map();

  wear(null);
  for (const stat of document.querySelectorAll(".ms-stat b")) {
    stat.textContent = "–";
  }
  for (const body of document.querySelectorAll(".view > div[id$='-body']")) {
    body.replaceChildren();
  }
  $("audit-notice").dataset.open = "0";
}

function showSignIn(message) {
  stopPolling();
  forget();
  $("shell").dataset.open = "0";
  $("signin").dataset.open = "1";
  $("signin-problem").textContent = message || "";
  $("signin-token").value = "";
  $("signin-token").focus();
}

function showShell() {
  $("signin").dataset.open = "0";
  $("shell").dataset.open = "1";
}

async function signIn(event) {
  event.preventDefault();
  const button = $("signin-go");
  button.disabled = true;

  try {
    const { ok, data, detail } = await api("POST", "/v1/console/session", {
      token: $("signin-token").value.trim(),
    });
    if (!ok) {
      $("signin-problem").textContent = detail || "sign in failed";
      return;
    }
    wear(data);
    showShell();
    await refresh();
    startPolling();
  } finally {
    button.disabled = false;
  }
}

async function signOut() {
  await api("DELETE", "/v1/console/session");
  showSignIn("");
}

function wear(me) {
  state.me = me;
  $("who").textContent = me ? me.user_name : "–";
  $("who-role").textContent = me ? me.role : "–";

  const held = me ? RANK[me.role] || 0 : 0;
  for (const link of document.querySelectorAll("#nav a")) {
    const needed = RANK[link.dataset.needs] || 0;
    link.dataset.reachable = held >= needed ? "1" : "0";
  }
}

function holds(role) {
  return state.me ? (RANK[state.me.role] || 0) >= RANK[role] : false;
}

function relative(iso) {
  if (!iso) return "–";
  const seconds = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (!Number.isFinite(seconds)) return iso;
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

function until(iso) {
  if (!iso) return "–";
  const seconds = Math.round((Date.parse(iso) - Date.now()) / 1000);
  if (!Number.isFinite(seconds)) return iso;
  if (seconds <= 0) return "expired";
  if (seconds < 60) return `${seconds}s left`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m left`;
  return `${Math.round(seconds / 3600)}h left`;
}

const TONES = ["ok", "danger", "warn", "info", "pending", "idle"];

function pill(tone, label) {
  const known = TONES.includes(tone) ? tone : "idle";
  return el("span", { class: `ms-pill ms-pill-${known}` }, el("i", {}), label);
}

function mono(text) {
  return el("span", { class: "ms-mono" }, text);
}

function table(headers, rows) {
  return el("table", { class: "ms-table" },
    el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, rows));
}

function empty(body, message) {
  body.replaceChildren(el("p", { class: "empty" }, message));
}

function refused(body, role) {
  empty(body, `Reading this needs the ${role} role. This account holds `
    + (state.me ? state.me.role : "less") + ".");
}

function targetName(id) {
  return state.targets.get(id) || id;
}

async function loadTargetNames() {
  const { ok, data } = await api("GET", "/v1/targets");
  if (!ok || !data) return;
  state.targets = new Map(data.targets.map((t) => [t.id, t.name]));
}

async function loadSessions() {
  const body = $("sessions-body");
  const { ok, status, data, detail } = await api("GET", "/v1/sessions");

  if (status === 403) return refused(body, "operator");
  if (!ok) return empty(body, detail || "the session list could not be read");

  const sessions = data.sessions || [];
  const active = sessions.filter((s) => s.active);
  $("stat-active").textContent = active.length;
  $("stat-total").textContent = sessions.length;

  if (sessions.length === 0) {
    return empty(body, "No session has been opened through this gateway yet.");
  }

  const rows = sessions.map((s) => el("tr", {},
    el("td", {}, s.active ? pill("ok", "active") : pill("idle", "closed")),
    el("td", {}, mono(s.id)),
    el("td", {}, s.user_name),
    el("td", {}, s.target_name),
    el("td", {}, mono(s.principal)),
    el("td", {}, relative(s.started_at)),
    el("td", {}, el("span", { class: "reason", title: s.reason || "" }, s.reason || "–")),
    el("td", { class: "actions" }, s.active
      ? el("button", { class: "ms-btn ms-btn-danger", onclick: () => kill(s) }, "Close")
      : null)));

  body.replaceChildren(table(
    ["State", "Session", "User", "Target", "Principal", "Started", "Reason", ""], rows));
}

async function kill(session) {
  const { ok, data, detail } = await api("POST", `/v1/sessions/${session.id}/kill`);
  if (!ok) {
    toast("bad", "Could not close it", detail);
    return;
  }
  if (data && data.killed) {
    toast("ok", "Session closed", `${session.user_name} on ${session.target_name}`);
  } else {
    toast("info", "Nothing was closed", (data && data.note) || "no socket for it is held here");
  }
  await refresh();
}

const REQUEST_TONES = {
  pending: "pending",
  approved: "ok",
  denied: "danger",
  cancelled: "idle",
  expired: "idle",
};

async function loadRequests() {
  const body = $("requests-body");
  const [requests] = await Promise.all([
    api("GET", "/v1/access-requests"),
    loadTargetNames(),
  ]);

  if (requests.status === 403) return refused(body, "operator");
  if (!requests.ok) return empty(body, requests.detail || "the request list could not be read");

  const all = requests.data.requests || [];
  $("stat-pending").textContent = all.filter((r) => r.state === "pending").length;
  $("stat-granted").textContent = all.filter((r) => r.state === "approved").length;

  if (all.length === 0) {
    return empty(body, "Nobody has asked for access yet.");
  }

  const rows = all.map((r) => el("tr", {},
    el("td", {}, pill(REQUEST_TONES[r.state] || "idle", r.state)),
    el("td", {}, mono(r.id)),
    el("td", {}, mono(r.requester_id)),
    el("td", {}, targetName(r.target_id)),
    el("td", {}, mono(r.principal)),
    el("td", {}, el("span", { class: "reason", title: r.reason }, r.reason)),
    el("td", {}, r.state === "approved" ? until(r.grant_expires_at) : relative(r.created_at)),
    el("td", { class: "actions" }, decisionsFor(r))));

  body.replaceChildren(table(
    ["State", "Request", "Requester", "Target", "Principal", "Reason", "Window", ""], rows));
}

function decisionsFor(request) {
  if (request.state !== "pending") return null;

  if (state.me && request.requester_id === state.me.user_id) {
    return [
      el("button", { class: "ms-btn", onclick: () => decide(request, "cancel") }, "Withdraw"),
      el("span", {
        class: "ms-chip",
        title: "A request cannot be decided by the account that raised it",
      }, "yours"),
    ];
  }

  if (!holds("admin")) return null;

  return [
    el("button", { class: "ms-btn ms-btn-primary", onclick: () => decide(request, "approve") }, "Approve"),
    el("button", { class: "ms-btn ms-btn-danger", onclick: () => decide(request, "deny") }, "Deny"),
  ];
}

const DECISIONS = {
  approve: "approved",
  deny: "denied",
  cancel: "withdrawn",
};

async function decide(request, verb) {
  const { ok, detail } = await api("POST", `/v1/access-requests/${request.id}/${verb}`);
  if (!ok) {
    toast("bad", `Could not ${verb} it`, detail);
    return;
  }
  toast("ok", `Request ${DECISIONS[verb]}`, request.reason);
  await refresh();
}

async function loadTargets() {
  const body = $("targets-body");
  const { ok, status, data, detail } = await api("GET", "/v1/targets");

  if (status === 403) return refused(body, "operator");
  if (!ok) return empty(body, detail || "the target list could not be read");

  const targets = data.targets || [];
  state.targets = new Map(targets.map((t) => [t.id, t.name]));

  const unpinned = targets.filter((t) => !t.host_key_fingerprint);
  $("stat-targets").textContent = targets.length;
  $("stat-unpinned").textContent = unpinned.length;

  if (targets.length === 0) {
    return empty(body, "No host has been registered yet. Until one is, there is nowhere to go.");
  }

  const rows = targets.map((t) => el("tr", {},
    el("td", {}, t.host_key_fingerprint
      ? pill("ok", "pinned")
      : pill("danger", "no host key")),
    el("td", {}, t.name),
    el("td", {}, mono(`${t.address}:${t.port}`)),
    el("td", {}, (t.principals || []).map((p) => el("span", { class: "ms-chip ms-mono" }, p))),
    el("td", {}, t.host_key_fingerprint
      ? el("span", { class: "reason ms-mono", title: t.host_key_fingerprint }, t.host_key_fingerprint)
      : el("span", { class: "ms-fg-faint" }, "sessions to it are refused")),
    el("td", {}, mono(t.id))));

  body.replaceChildren(table(
    ["Host key", "Name", "Address", "Principals", "Fingerprint", "Id"], rows));
}

async function loadPolicies() {
  const body = $("policies-body");
  const [policies] = await Promise.all([
    api("GET", "/v1/policies"),
    loadTargetNames(),
  ]);

  if (policies.status === 403) return refused(body, "admin");
  if (!policies.ok) return empty(body, policies.detail || "the policy list could not be read");

  const all = policies.data.policies || [];
  $("stat-policies").textContent = all.length;

  if (all.length === 0) {
    return empty(body, "No policy exists, so nothing can be granted to anyone.");
  }

  const rows = all.map((p) => el("tr", {},
    el("td", {}, p.name),
    el("td", {}, el("span", { class: "ms-chip" }, p.subject_kind), " ", mono(p.subject_id)),
    el("td", {}, targetName(p.target_id)),
    el("td", {}, (p.principals || []).map((v) => el("span", { class: "ms-chip ms-mono" }, v))),
    el("td", {}, relative(p.created_at))));

  body.replaceChildren(table(
    ["Policy", "Subject", "Target", "May land as", "Created"], rows));
}

const OUTCOME_TONES = {
  allowed: "ok",
  denied: "danger",
  error: "warn",
};

async function loadAudit() {
  const body = $("audit-body");
  const notice = $("audit-notice");
  const { ok, status, data, detail } = await api("GET", `/v1/audit?limit=${AUDIT_LIMIT}`);

  if (status === 403) {
    notice.dataset.open = "0";
    return refused(body, "admin");
  }
  if (!ok) {
    notice.dataset.open = "0";
    return empty(body, detail || "the trail could not be read");
  }

  const events = data.events || [];
  $("stat-events").textContent = events.length;
  $("stat-denied").textContent = events.filter((e) => e.outcome === "denied").length;

  notice.dataset.open = "1";
  notice.textContent = data.shipped
    ? `Showing the last ${events.length} events written on this host. They are also shipped off it.`
    : `Showing the last ${events.length} events. Nothing ships this trail anywhere, so it survives `
      + "a crash but not whoever owns this host. Start the gateway with --audit-loki-url to change that.";
  notice.dataset.tone = data.shipped ? "ok" : "warn";

  if (events.length === 0) {
    return empty(body, "The trail is empty.");
  }

  const rows = events.map((e) => el("tr", {},
    el("td", {}, mono(e.at.replace("T", " ").replace("Z", ""))),
    el("td", {}, pill(OUTCOME_TONES[e.outcome] || "idle", e.outcome || "allowed")),
    el("td", {}, mono(e.action)),
    el("td", {}, e.actor_name || el("span", { class: "ms-fg-faint" }, "system")),
    el("td", {}, e.object ? mono(e.object) : "–"),
    el("td", {}, el("span", { class: "reason", title: describe(e) }, describe(e)))));

  body.replaceChildren(table(
    ["When (UTC)", "Outcome", "Action", "Actor", "Object", "Detail"], rows));
}

function describe(event) {
  const parts = [];
  if (event.reason) parts.push(event.reason);
  for (const [key, value] of Object.entries(event.fields || {})) {
    parts.push(`${key}=${value}`);
  }
  return parts.join("  ") || "–";
}

const VIEWS = {
  sessions: loadSessions,
  requests: loadRequests,
  targets: loadTargets,
  policies: loadPolicies,
  audit: loadAudit,
};

async function refresh() {
  const version = await api("GET", "/v1/version");
  if (version.status === 401) return;

  const health = $("health");
  health.className = `ms-pill ms-pill-${version.ok ? "ok" : "danger"}`;
  health.replaceChildren(el("i", {}), version.ok ? "healthy" : "unreachable");
  if (version.ok && version.data) {
    $("version").textContent = version.data.version;
  }

  await VIEWS[state.view]();
  $("stamp").textContent = new Date().toLocaleTimeString();
}

function startPolling() {
  stopPolling();
  if ($("auto").checked) {
    state.timer = setInterval(refresh, REFRESH_MS);
  }
}

function stopPolling() {
  if (state.timer) {
    clearInterval(state.timer);
    state.timer = null;
  }
}

function showView(name) {
  state.view = name;
  for (const view of document.querySelectorAll(".view")) {
    view.dataset.open = view.id === `view-${name}` ? "1" : "0";
  }
  for (const link of document.querySelectorAll("#nav a")) {
    if (link.dataset.view === name) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  }
}

function routeFromHash() {
  const name = location.hash.replace("#", "");
  showView(Object.hasOwn(VIEWS, name) ? name : "sessions");
}

async function onRoute() {
  routeFromHash();
  if (state.me) await refresh();
}

async function start() {
  const { ok, data } = await api("GET", "/v1/console/whoami");
  if (!ok) {
    showSignIn("");
    return;
  }
  wear(data);
  showShell();
  await refresh();
  startPolling();
}

$("signin-form").addEventListener("submit", signIn);
$("signout").addEventListener("click", signOut);
$("refresh").addEventListener("click", refresh);
$("auto").addEventListener("change", startPolling);
window.addEventListener("hashchange", onRoute);

routeFromHash();
start();
