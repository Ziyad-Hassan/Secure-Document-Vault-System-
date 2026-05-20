/* ================================================
   Verify Page — Document integrity + signature check
   ================================================ */

document.addEventListener("DOMContentLoaded", async () => {
  requireAuth();
  document.getElementById("logout-btn").addEventListener("click", async () => {
    await api("POST", "/auth/logout"); Auth.clear(); window.location.href = "/";
  });

  // Allow Enter key in ID input
  document.getElementById("doc-id-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") verifyDocument();
  });

  await loadDocumentList();

  // Pre-fill from URL query param: ?id=5
  const params = new URLSearchParams(window.location.search);
  const preId = params.get("id");
  if (preId) {
    document.getElementById("doc-id-input").value = preId;
    verifyDocument();
  }
});

async function loadDocumentList() {
  const { ok, data } = await api("GET", "/documents");
  const loadingEl = document.getElementById("doc-select-loading");
  const selectEl  = document.getElementById("doc-select");

  if (!ok || !data.documents.length) {
    loadingEl.textContent = "No documents found.";
    return;
  }

  loadingEl.style.display = "none";
  selectEl.style.display  = "block";

  data.documents.forEach(doc => {
    const opt = document.createElement("option");
    opt.value = doc.id;
    opt.textContent = `#${doc.id} — ${doc.original_filename} (${doc.file_size_readable})`;
    selectEl.appendChild(opt);
  });
}

async function verifyDocument() {
  const docId = document.getElementById("doc-id-input").value.trim();
  if (!docId) { showToast("Please enter a Document ID.", "error"); return; }

  const btn = document.getElementById("verify-btn");
  setLoading(btn, true);

  document.getElementById("result-area").style.display = "none";

  const { ok, data } = await api("POST", `/documents/${docId}/verify`);
  setLoading(btn, false);

  if (!ok) {
    if (data.status === 404) {
      showToast("Document not found or access denied.", "error");
    } else {
      showToast(data.error || "Verification failed.", "error");
    }
    return;
  }

  renderResult(data);
}

function renderResult(r) {
  const area = document.getElementById("result-area");
  const card = document.getElementById("result-card");

  area.style.display = "block";

  const overallOk = r.verified;
  const overallColor = overallOk ? "var(--success)" : "var(--danger)";
  const overallIcon  = overallOk ? "✅" : "❌";
  const overallLabel = overallOk ? "VERIFIED — File is intact and authentic" : "TAMPERED — File may have been modified!";

  // Integrity check row
  const integrityOk   = r.integrity_check;
  const integrityIcon = integrityOk ? "✅" : "❌";

  // Signature check row
  const sigCheck = r.signature_check;
  const sigIcon  = sigCheck === true ? "✅" : sigCheck === false ? "❌" : "⚠️";
  const sigLabel = sigCheck === true ? "Valid" : sigCheck === false ? "Invalid" : "Not available";

  card.innerHTML = `
    <!-- Overall verdict -->
    <div style="display:flex;align-items:center;gap:16px;padding:20px;
      background:${overallOk ? "rgba(87,204,153,.08)" : "rgba(231,111,81,.08)"};
      border-radius:var(--radius);margin-bottom:24px;
      border:1px solid ${overallOk ? "rgba(87,204,153,.3)" : "rgba(231,111,81,.3)"};">
      <span style="font-size:2.5rem;">${overallIcon}</span>
      <div>
        <div style="font-weight:800;font-size:1rem;color:${overallColor};">${overallLabel}</div>
        <div class="text-muted" style="font-size:.8rem;margin-top:2px;">
          Document #${r.document_id} — ${escHtml(r.filename)}
        </div>
      </div>
    </div>

    <!-- Checks grid -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:24px;">

      <div style="padding:16px;background:var(--bg-input);border-radius:var(--radius);border:1px solid var(--border);">
        <div style="font-size:.72rem;font-family:var(--font-mono);color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;">
          Integrity Check (SHA-256)
        </div>
        <div style="display:flex;align-items:center;gap:8px;font-weight:600;">
          ${integrityIcon} ${integrityOk ? "Hashes match" : "HASH MISMATCH"}
        </div>
        ${!integrityOk && r.details.integrity_error ?
          `<div style="color:var(--danger);font-size:.78rem;margin-top:6px;">${r.details.integrity_error}</div>` : ""}
      </div>

      <div style="padding:16px;background:var(--bg-input);border-radius:var(--radius);border:1px solid var(--border);">
        <div style="font-size:.72rem;font-family:var(--font-mono);color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;">
          Digital Signature (RSA-SHA256)
        </div>
        <div style="display:flex;align-items:center;gap:8px;font-weight:600;">
          ${sigIcon} ${sigLabel}
        </div>
        ${r.details.signed_by ?
          `<div class="text-muted" style="font-size:.78rem;margin-top:4px;">Signed by: ${r.details.signed_by}</div>` : ""}
        ${r.details.signature_warning ?
          `<div style="color:var(--warning);font-size:.78rem;margin-top:6px;">${r.details.signature_warning}</div>` : ""}
      </div>
    </div>

    <!-- Hash comparison -->
    <div style="margin-bottom:16px;">
      <div style="font-size:.75rem;font-family:var(--font-mono);color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;">
        Hash Comparison
      </div>
      <div style="display:grid;gap:8px;">
        <div style="padding:10px 14px;background:var(--bg-input);border-radius:var(--radius);border:1px solid var(--border);">
          <span style="font-size:.7rem;color:var(--text-muted);font-family:var(--font-mono);">STORED AT UPLOAD:</span>
          <div style="font-family:var(--font-mono);font-size:.8rem;word-break:break-all;margin-top:3px;">${r.stored_hash}</div>
        </div>
        <div style="padding:10px 14px;background:var(--bg-input);border-radius:var(--radius);
          border:1px solid ${integrityOk ? "rgba(87,204,153,.3)" : "rgba(231,111,81,.3)"};">
          <span style="font-size:.7rem;color:var(--text-muted);font-family:var(--font-mono);">CURRENT (RECOMPUTED):</span>
          <div style="font-family:var(--font-mono);font-size:.8rem;word-break:break-all;margin-top:3px;
            color:${integrityOk ? "var(--success)" : "var(--danger)"};">${r.current_hash || "—"}</div>
        </div>
      </div>
    </div>

    <div style="display:flex;gap:10px;margin-top:4px;">
      <button class="btn btn-ghost" style="flex:1;" onclick="location.href='/pages/dashboard.html'">← Back to Documents</button>
      <button class="btn btn-primary" style="flex:1;" onclick="downloadVerifiedDoc(${r.document_id}, '${escHtml(r.filename)}')">⬇ Download</button>
    </div>
  `;
}

async function downloadVerifiedDoc(id, filename) {
  showToast("Preparing download…", "info");
  const token = Auth.getAccessToken();
  const res = await fetch(`${window.location.origin}/api/documents/${id}/download`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!res.ok) { showToast("Download failed.", "error"); return; }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function escHtml(str) {
  return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
