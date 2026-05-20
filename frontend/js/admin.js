/* ================================================
   Admin Panel — Users, Documents, Stats
   ================================================ */

let allUsers = [];
let roleTargetId = null;

document.addEventListener("DOMContentLoaded", () => {
  requireRole("admin", "manager");

  document.getElementById("logout-btn").addEventListener("click", async () => {
    await api("POST", "/auth/logout"); Auth.clear(); window.location.href = "/";
  });

  // Load default tab
  loadUsers();
});

// ── Tabs ──────────────────────────────────────
function showTab(name) {
  ["users","documents","stats"].forEach(t => {
    document.getElementById(`tab-${t}`).style.display = t === name ? "block" : "none";
  });
  // Update sidebar active
  document.querySelectorAll(".sidebar .nav-link").forEach((btn, i) => {
    btn.classList.toggle("active", ["users","documents","stats"][i] === name);
  });

  if (name === "documents") loadAllDocs();
  if (name === "stats")     loadStats();
}

// ── Users Tab ─────────────────────────────────
async function loadUsers() {
  const { ok, data } = await api("GET", "/admin/users");
  document.getElementById("users-loading").style.display = "none";

  if (!ok) { showToast(data.error || "Failed to load users.", "error"); return; }

  allUsers = data.users;
  renderUsers(allUsers);
  document.getElementById("users-card").style.display = "block";
}

function renderUsers(users) {
  const tbody = document.getElementById("users-tbody");
  tbody.innerHTML = users.map(u => `
    <tr>
      <td class="text-mono" style="font-size:.8rem;color:var(--text-muted);">${u.id}</td>
      <td style="font-weight:600;">${escHtml(u.username)}</td>
      <td class="text-muted" style="font-size:.85rem;">${escHtml(u.email)}</td>
      <td><span class="badge badge-${u.role}">${u.role.toUpperCase()}</span></td>
      <td style="text-align:center;">${u.is_2fa_enabled ? "✅" : "—"}</td>
      <td style="text-align:center;font-size:.8rem;color:var(--text-muted);">
        ${u.oauth_provider ? `<span style="text-transform:capitalize">${u.oauth_provider}</span>` : "—"}
      </td>
      <td class="text-mono" style="font-size:.8rem;text-align:center;">${u.document_count || 0}</td>
      <td>
        <span class="badge ${u.is_active ? "badge-success" : "badge-danger"}">
          ${u.is_active ? "Active" : "Disabled"}
        </span>
      </td>
      <td>
        <div style="display:flex;gap:5px;">
          <button class="btn btn-sm" title="Change Role"
            onclick="openRoleModal(${u.id}, '${escHtml(u.username)}', '${u.role}')">
            🎭
          </button>
          <button class="btn btn-sm" title="${u.is_active ? "Deactivate" : "Activate"}"
            onclick="toggleUser(${u.id})">
            ${u.is_active ? "🚫" : "✅"}
          </button>
          <button class="btn btn-sm btn-danger" title="Delete User"
            onclick="deleteUser(${u.id}, '${escHtml(u.username)}')">🗑</button>
        </div>
      </td>
    </tr>
  `).join("");
}

function filterUsers(q) {
  const filtered = allUsers.filter(u =>
    u.username.toLowerCase().includes(q.toLowerCase()) ||
    u.email.toLowerCase().includes(q.toLowerCase())
  );
  renderUsers(filtered);
}

// ── Role Modal ────────────────────────────────
function openRoleModal(userId, username, currentRole) {
  roleTargetId = userId;
  document.getElementById("role-modal-username").textContent = username;
  document.getElementById("role-select").value = currentRole;
  document.getElementById("role-modal").style.display = "grid";
  document.getElementById("confirm-role-btn").onclick = confirmRoleChange;
}

function closeRoleModal() {
  document.getElementById("role-modal").style.display = "none";
  roleTargetId = null;
}

async function confirmRoleChange() {
  const role = document.getElementById("role-select").value;
  const btn  = document.getElementById("confirm-role-btn");
  setLoading(btn, true);
  const { ok, data } = await api("PATCH", `/admin/users/${roleTargetId}/role`, { role });
  setLoading(btn, false);
  if (!ok) { showToast(data.error, "error"); return; }
  showToast(data.message, "success");
  closeRoleModal();
  loadUsers();
}

// ── Toggle user active ─────────────────────────
async function toggleUser(userId) {
  const { ok, data } = await api("PATCH", `/admin/users/${userId}/toggle`);
  if (!ok) { showToast(data.error || "Failed.", "error"); return; }
  showToast(data.message, "success");
  loadUsers();
}

// ── Delete user ────────────────────────────────
async function deleteUser(userId, username) {
  if (!confirm(`Delete user "${username}" and all their documents? This cannot be undone.`)) return;
  const { ok, data } = await api("DELETE", `/admin/users/${userId}`);
  if (!ok) { showToast(data.error, "error"); return; }
  showToast(data.message, "success");
  loadUsers();
}

// ── Documents Tab ─────────────────────────────
async function loadAllDocs() {
  document.getElementById("all-docs-loading").style.display = "block";
  document.getElementById("all-docs-card").style.display = "none";

  const { ok, data } = await api("GET", "/admin/documents");
  document.getElementById("all-docs-loading").style.display = "none";
  if (!ok) { showToast("Failed to load documents.", "error"); return; }

  const tbody = document.getElementById("all-docs-tbody");
  tbody.innerHTML = data.documents.map(doc => `
    <tr>
      <td class="text-mono" style="font-size:.78rem;color:var(--text-muted);">${doc.id}</td>
      <td style="font-weight:600;font-size:.875rem;">${escHtml(doc.original_filename)}</td>
      <td class="text-muted" style="font-size:.85rem;">${escHtml(doc.owner || "—")}</td>
      <td class="text-mono" style="font-size:.78rem;color:var(--text-muted);">${doc.file_size_readable}</td>
      <td style="text-align:center;">${doc.is_encrypted  ? '<span class="badge badge-success">AES-256</span>' : "—"}</td>
      <td style="text-align:center;">${doc.has_signature ? '<span class="badge badge-manager">RSA</span>'   : "—"}</td>
      <td style="text-align:center;">
        ${doc.is_verified
          ? '<span class="badge badge-success">✓</span>'
          : `<button class="btn btn-sm" onclick="approveDoc(${doc.id})">Approve</button>`
        }
      </td>
      <td class="text-muted" style="font-size:.78rem;">${formatDate(doc.uploaded_at)}</td>
      <td>
        <button class="btn btn-sm" onclick="location.href='/pages/verify.html?id=${doc.id}'">🔍</button>
      </td>
    </tr>
  `).join("");

  document.getElementById("all-docs-card").style.display = "block";
}

async function approveDoc(docId) {
  const { ok, data } = await api("PATCH", `/documents/${docId}/approve`);
  if (!ok) { showToast(data.error || "Failed.", "error"); return; }
  showToast(data.message, "success");
  loadAllDocs();
}

// ── Stats Tab ─────────────────────────────────
async function loadStats() {
  document.getElementById("stats-loading").style.display = "block";
  document.getElementById("stats-content").style.display = "none";

  const { ok, data } = await api("GET", "/admin/stats");
  document.getElementById("stats-loading").style.display = "none";
  if (!ok) { showToast("Failed to load stats.", "error"); return; }

  const el = document.getElementById("stats-content");
  el.style.display = "block";

  const roles = data.users.by_role;
  el.innerHTML = `
    <div class="stats-grid" style="grid-template-columns:repeat(3,1fr);">
      <div class="stat-card">
        <div class="stat-value">${data.users.total}</div>
        <div class="stat-label">Total Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color:var(--success);">${data.users.active}</div>
        <div class="stat-label">Active Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color:var(--primary);">${data.users.with_2fa}</div>
        <div class="stat-label">Users with 2FA</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${data.documents.total}</div>
        <div class="stat-label">Total Documents</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color:var(--success);">${data.documents.verified}</div>
        <div class="stat-label">Verified Docs</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color:var(--accent);">${data.storage.total_readable}</div>
        <div class="stat-label">Encrypted Storage</div>
      </div>
    </div>

    <div class="card" style="margin-top:24px;">
      <div class="card-title" style="margin-bottom:16px;">Role Distribution</div>
      <div style="display:flex;flex-direction:column;gap:10px;">
        ${Object.entries(roles).map(([role, count]) => `
          <div style="display:flex;align-items:center;gap:12px;">
            <span class="badge badge-${role}" style="width:80px;justify-content:center;">${role}</span>
            <div style="flex:1;height:8px;background:var(--bg-input);border-radius:999px;overflow:hidden;">
              <div style="height:100%;border-radius:999px;background:var(--primary);
                width:${data.users.total > 0 ? Math.round((count/data.users.total)*100) : 0}%;
                transition:width .5s;"></div>
            </div>
            <span class="text-mono" style="font-size:.85rem;color:var(--text-muted);min-width:30px;text-align:right;">
              ${count}
            </span>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function escHtml(str) {
  return String(str || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
