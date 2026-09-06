const REFRESH_MS = 5000;
const CONSOLE_HEADER = "X-Marac-Console";

const state = {
  sessions: [],
  requests: [],
  sessionsDenied: false,
  requestsDenied: false,
  me: null,
  timer: null,
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
  const options = { method, headers: { [CONSOLE_HEADER]: "1" } };
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
  state.sessions = [];
  state.requests = [];
  state.sessionsDenied = false;
  state.requestsDenied = false;
  state.me = null;

  wear(null);
  for (const id of ["stat-active", "stat-total", "stat-pending", "stat-granted"]) {
    $(id).textContent = "–";
  }
  $("sessions-body").replaceChildren();
  $("requests-body").replaceChildren();
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

function pill(state_, label) {
  return el("span", { class: `ms-pill ms-pill-${state_}` }, el("i", {}), label);
}

const REQUEST_STATES = {
  pending: "pending",
  approved: "ok",
  denied: "danger",
  cancelled: "idle",
  expired: "idle",
};

function table(headers, rows) {
  return el("table", { class: "ms-table" },
    el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, rows));
}

function renderSessions() {
  const body = $("sessions-body");
  body.replaceChildren();

  const active = state.sessions.filter((s) => s.active);
  $("stat-active").textContent = active.length;
  $("stat-total").textContent = state.sessions.length;

  if (state.sessionsDenied) {
    body.append(el("p", { class: "empty" },
      "Reading sessions needs the operator role. This account holds "
      + (state.me ? state.me.role : "less") + "."));
    return;
  }

  if (state.sessions.length === 0) {
    body.append(el("p", { class: "empty" }, "No session has been opened through this gateway yet."));
    return;
  }

  const rows = state.sessions.map((s) => el("tr", {},
    el("td", {}, s.active ? pill("ok", "active") : pill("idle", "closed")),
    el("td", {}, el("span", { class: "ms-mono" }, s.id)),
    el("td", {}, s.user_name),
    el("td", {}, s.target_name),
    el("td", {}, el("span", { class: "ms-mono" }, s.principal)),
    el("td", {}, relative(s.started_at)),
    el("td", {}, el("span", { class: "reason", title: s.reason || "" }, s.reason || "–")),
    el("td", { class: "actions" }, s.active
      ? el("button", {
          class: "ms-btn ms-btn-danger",
          onclick: () => kill(s),
        }, "Close")
      : null)));

  body.append(table(
    ["State", "Session", "User", "Target", "Principal", "Started", "Reason", ""],
    rows));
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

function renderRequests() {
  const body = $("requests-body");
  body.replaceChildren();

  const pending = state.requests.filter((r) => r.state === "pending");
  const granted = state.requests.filter((r) => r.state === "approved");
  $("stat-pending").textContent = pending.length;
  $("stat-granted").textContent = granted.length;

  if (state.requestsDenied) {
    body.append(el("p", { class: "empty" },
      "Reading access requests needs the operator role. This account holds "
      + (state.me ? state.me.role : "less") + "."));
    return;
  }

  if (state.requests.length === 0) {
    body.append(el("p", { class: "empty" }, "Nobody has asked for access yet."));
    return;
  }

  const mine = (r) => state.me && r.requester_id === state.me.user_id;
  const admin = state.me && state.me.role === "admin";

  const rows = state.requests.map((r) => el("tr", {},
    el("td", {}, pill(REQUEST_STATES[r.state] || "idle", r.state)),
    el("td", {}, el("span", { class: "ms-mono" }, r.id)),
    el("td", {}, el("span", { class: "ms-mono" }, r.requester_id)),
    el("td", {}, el("span", { class: "ms-mono" }, r.principal)),
    el("td", {}, el("span", { class: "reason", title: r.reason }, r.reason)),
    el("td", {}, r.state === "approved" ? until(r.grant_expires_at) : relative(r.created_at)),
    el("td", { class: "actions" }, decisionsFor(r, mine(r), admin))));

  body.append(table(
    ["State", "Request", "Requester", "Principal", "Reason", "Window", ""],
    rows));
}

function decisionsFor(request, isMine, isAdmin) {
  if (request.state !== "pending") return null;

  if (isMine) {
    return [
      el("button", {
        class: "ms-btn",
        onclick: () => decide(request, "cancel"),
      }, "Withdraw"),
      el("span", { class: "ms-chip", title: "A request cannot be decided by the account that raised it" },
        "yours"),
    ];
  }

  if (!isAdmin) return null;

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

async function refresh() {
  const [version, sessions, requests] = await Promise.all([
    api("GET", "/v1/version"),
    api("GET", "/v1/sessions"),
    api("GET", "/v1/access-requests"),
  ]);

  if (version.status === 401) return;

  state.sessions = sessions.ok && sessions.data ? sessions.data.sessions : [];
  state.requests = requests.ok && requests.data ? requests.data.requests : [];
  state.sessionsDenied = sessions.status === 403;
  state.requestsDenied = requests.status === 403;

  const health = $("health");
  health.className = `ms-pill ms-pill-${version.ok ? "ok" : "danger"}`;
  health.replaceChildren(el("i", {}), version.ok ? "healthy" : "unreachable");

  if (version.ok && version.data) {
    $("version").textContent = version.data.version;
  }
  $("stamp").textContent = new Date().toLocaleTimeString();

  renderSessions();
  renderRequests();
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
  const name = location.hash.replace("#", "") || "sessions";
  showView(name === "requests" ? "requests" : "sessions");
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
window.addEventListener("hashchange", routeFromHash);

routeFromHash();
start();
