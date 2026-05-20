/* ================================================
   Secure Document Vault — Shared JS Utilities
   ================================================ */

// ── API Base URL ──────────────────────────────────
const API_BASE = window.location.origin + "/api";

// ── Token Storage ─────────────────────────────────
const Auth = {
  getAccessToken()  { return localStorage.getItem("access_token"); },
  getRefreshToken() { return localStorage.getItem("refresh_token"); },
  getUser()         { const u = localStorage.getItem("user"); return u ? JSON.parse(u) : null; },
  setTokens(access, refresh) {
    localStorage.setItem("access_token", access);
    localStorage.setItem("refresh_token", refresh);
  },
  setUser(user) { localStorage.setItem("user", JSON.stringify(user)); },
  clear() {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    localStorage.removeItem("user");
  },
  isLoggedIn() { return !!this.getAccessToken(); },
  getRole()    { const u = this.getUser(); return u ? u.role : null; },
};

// ── API Helper ─────────────────────────────────────
async function api(method, path, body = null, auth = true) {
  const headers = { "Content-Type": "application/json" };
  if (auth) {
    const token = Auth.getAccessToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });

  // Try to refresh token if 401 and we have a refresh token
  if (res.status === 401 && auth) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      // Retry the original request with new token
      headers["Authorization"] = `Bearer ${Auth.getAccessToken()}`;
      const retry = await fetch(`${API_BASE}${path}`, {
        method, headers,
        body: body ? JSON.stringify(body) : null,
      });
      return { ok: retry.ok, status: retry.status, data: await retry.json() };
    } else {
      Auth.clear();
      window.location.href = "/";
      return;
    }
  }

  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

async function tryRefresh() {
  const refreshToken = Auth.getRefreshToken();
  if (!refreshToken) return false;
  try {
    const res = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    Auth.setTokens(data.access_token, Auth.getRefreshToken());
    if (data.user) Auth.setUser(data.user);
    return true;
  } catch { return false; }
}

// FormData upload (for files)
async function apiUpload(path, formData) {
  const token = Auth.getAccessToken();
  const headers = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST", headers, body: formData,
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

// ── Toast Notifications ────────────────────────────
function showToast(message, type = "info", duration = 3500) {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    document.body.appendChild(container);
  }

  const icons = { success: "✓", error: "✕", info: "ℹ" };
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type] || "ℹ"}</span><span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = "none";
    toast.style.opacity = "0";
    toast.style.transform = "translateX(20px)";
    toast.style.transition = "all 0.25s";
    setTimeout(() => toast.remove(), 260);
  }, duration);
}

// ── Route Guard ────────────────────────────────────
function requireAuth() {
  if (!Auth.isLoggedIn()) {
    window.location.href = "/";
  }
}

function requireRole(...roles) {
  requireAuth();
  if (!roles.includes(Auth.getRole())) {
    showToast(`Access denied. Required: ${roles.join(" or ")}`, "error");
    setTimeout(() => window.location.href = "/pages/dashboard.html", 1500);
  }
}

function redirectIfLoggedIn(dest = "/pages/dashboard.html") {
  if (Auth.isLoggedIn()) window.location.href = dest;
}

// ── Format Helpers ─────────────────────────────────
function formatDate(isoString) {
  if (!isoString) return "—";
  return new Date(isoString).toLocaleDateString("en-US", {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit"
  });
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  return `${bytes.toFixed(1)} ${units[i]}`;
}

// ── DOM Helpers ────────────────────────────────────
function $(sel, ctx = document) { return ctx.querySelector(sel); }
function $$(sel, ctx = document) { return [...ctx.querySelectorAll(sel)]; }

function setLoading(btn, loading) {
  if (loading) {
    btn.disabled = true;
    btn.dataset.origText = btn.textContent;
    btn.textContent = "";
    btn.classList.add("btn-loading");
  } else {
    btn.disabled = false;
    btn.textContent = btn.dataset.origText || btn.textContent;
    btn.classList.remove("btn-loading");
  }
}

function showAlert(containerId, message, type = "error") {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
}

function clearAlert(containerId) {
  const el = document.getElementById(containerId);
  if (el) el.innerHTML = "";
}
