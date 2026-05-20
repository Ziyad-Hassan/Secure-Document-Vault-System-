/* ================================================
   Upload Page — Drag/drop, hash preview, upload
   ================================================ */

let selectedFile = null;

document.addEventListener("DOMContentLoaded", () => {
  requireAuth();
  document.getElementById("logout-btn").addEventListener("click", async () => {
    await api("POST", "/auth/logout");
    Auth.clear(); window.location.href = "/";
  });
  initDropZone();
});

// ── Drop Zone ──────────────────────────────────
function initDropZone() {
  const zone  = document.getElementById("drop-zone");
  const input = document.getElementById("file-input");

  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("drag-over");
  });
  zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("drag-over");
    const file = e.dataTransfer.files[0];
    if (file) handleFileSelect(file);
  });
  input.addEventListener("change", (e) => {
    if (e.target.files[0]) handleFileSelect(e.target.files[0]);
  });
}

async function handleFileSelect(file) {
  const allowed = ["pdf","docx","txt","png","jpg","jpeg"];
  const ext = file.name.split(".").pop().toLowerCase();
  if (!allowed.includes(ext)) {
    showAlert("alert-area", `File type .${ext} is not allowed. Allowed: ${allowed.join(", ")}`, "error");
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    showAlert("alert-area", "File is too large. Maximum size is 10 MB.", "error");
    return;
  }

  selectedFile = file;
  clearAlert("alert-area");

  // Show preview
  document.getElementById("drop-zone").style.display     = "none";
  document.getElementById("file-preview").style.display  = "flex";
  document.getElementById("file-preview").style.flexDirection = "column";

  const icons = { pdf:"📕", docx:"📘", txt:"📄", png:"🖼", jpg:"🖼", jpeg:"🖼" };
  document.getElementById("file-icon").textContent = icons[ext] || "📄";
  document.getElementById("file-name").textContent = file.name;
  document.getElementById("file-meta").textContent =
    `${formatBytes(file.size)} • ${file.type || "unknown type"} • .${ext}`;

  document.getElementById("upload-btn").disabled = false;

  // Compute SHA-256 client-side for preview
  computeHashPreview(file);

  // Activate step 1 in sidebar
  activateStep(1);
}

async function computeHashPreview(file) {
  try {
    const buf  = await file.arrayBuffer();
    const hash = await crypto.subtle.digest("SHA-256", buf);
    const hex  = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,"0")).join("");
    document.getElementById("hash-preview").style.display = "block";
    document.getElementById("hash-value").textContent = hex;
  } catch (e) {
    console.warn("Client-side hash failed:", e);
  }
}

function clearFile() {
  selectedFile = null;
  document.getElementById("drop-zone").style.display = "block";
  document.getElementById("file-preview").style.display = "none";
  document.getElementById("upload-btn").disabled = true;
  document.getElementById("file-input").value = "";
  clearAlert("alert-area");
  [1,2,3,4,5].forEach(i => deactivateStep(i));
}

// ── Upload ─────────────────────────────────────
async function uploadFile() {
  if (!selectedFile) return;

  const btn = document.getElementById("upload-btn");
  const desc = document.getElementById("description").value.trim();

  setLoading(btn, true);
  clearAlert("alert-area");

  // Show progress
  document.getElementById("progress-section").style.display = "block";
  document.getElementById("file-preview").style.display = "none";

  const steps = [
    { label: "Computing SHA-256 hash…",       icon: "#️⃣" },
    { label: "Creating RSA-SHA256 signature…", icon: "✍" },
    { label: "Encrypting with AES-256-GCM…",  icon: "🔒" },
    { label: "Uploading to server…",           icon: "⬆" },
    { label: "Saving metadata to database…",   icon: "💾" },
  ];

  const progressEl = document.getElementById("progress-steps");
  progressEl.innerHTML = steps.map((s, i) => `
    <div id="ps-${i}" style="display:flex;align-items:center;gap:10px;opacity:.35;transition:.3s;">
      <span style="font-size:1rem;">${s.icon}</span>
      <span style="font-size:.875rem;">${s.label}</span>
      <span id="ps-${i}-check" style="margin-left:auto;"></span>
    </div>
  `).join("");

  // Animate steps (simulated — real work happens server-side)
  for (let i = 0; i < steps.length - 1; i++) {
    activateProgressStep(i);
    await sleep(400 + Math.random() * 300);
    doneProgressStep(i);
    activateStep(i + 2);
  }

  // Actually upload
  activateProgressStep(4);
  const formData = new FormData();
  formData.append("file", selectedFile);
  if (desc) formData.append("description", desc);

  const { ok, data } = await apiUpload("/documents/upload", formData);
  setLoading(btn, false);

  if (!ok) {
    document.getElementById("progress-section").style.display = "none";
    document.getElementById("file-preview").style.display = "flex";
    showAlert("alert-area", data.error || "Upload failed.", "error");
    return;
  }

  doneProgressStep(4);
  activateStep(5);

  // Show success
  await sleep(400);
  document.getElementById("progress-section").style.display = "none";
  document.getElementById("success-section").style.display  = "block";

  const doc = data.document;
  document.getElementById("result-details").innerHTML = `
    <div>📄 Filename:       <strong>${doc.original_filename}</strong></div>
    <div>📦 Size:           <strong>${doc.file_size_readable}</strong></div>
    <div>#️⃣ SHA-256:       <strong style="word-break:break-all;">${doc.sha256_hash}</strong></div>
    <div>🔒 Encrypted:      <strong>${doc.is_encrypted ? "AES-256-GCM ✓" : "No"}</strong></div>
    <div>✍ Signed:          <strong>${doc.has_signature ? "RSA-SHA256 ✓" : "No"}</strong></div>
    <div>🆔 Document ID:    <strong>${doc.id}</strong></div>
    <div>📅 Uploaded:       <strong>${formatDate(doc.uploaded_at)}</strong></div>
  `;
}

function resetForm() {
  selectedFile = null;
  document.getElementById("file-input").value = "";
  document.getElementById("description").value = "";
  document.getElementById("drop-zone").style.display = "block";
  document.getElementById("success-section").style.display = "none";
  document.getElementById("upload-btn").disabled = true;
  [1,2,3,4,5].forEach(i => deactivateStep(i));
}

// ── Helpers ───────────────────────────────────
function activateStep(n) {
  const el = document.getElementById(`step-${n}`);
  if (el) el.style.opacity = "1";
}
function deactivateStep(n) {
  const el = document.getElementById(`step-${n}`);
  if (el) el.style.opacity = n === 1 ? "1" : "0.4";
}
function activateProgressStep(i) {
  const el = document.getElementById(`ps-${i}`);
  if (el) { el.style.opacity = "1"; el.style.fontWeight = "600"; }
}
function doneProgressStep(i) {
  const el = document.getElementById(`ps-${i}-check`);
  if (el) { el.textContent = "✓"; el.style.color = "var(--success)"; }
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
