/* ================================================
   Secure Document Vault — Dashboard Logic
   Handles: User info, Document listing, Stats, 2FA Modal
   ================================================ */

let allDocuments = [];
let deleteDocId = null;

document.addEventListener("DOMContentLoaded", () => {
    // 1. Check if user is logged in
    if (!Auth.isLoggedIn()) {
        window.location.href = "/index.html";
        return;
    }

    const user = Auth.getUser();

    // 2. Populate User Info in Sidebar
    document.getElementById("sidebar-username").textContent = user.username || "User";
    document.getElementById("sidebar-role").textContent = user.role ? user.role.toUpperCase() : "USER";
    document.getElementById("avatar").textContent = (user.username || "U").charAt(0).toUpperCase();

    // Show Admin Link if user is admin
    if (user.role === "admin") {
        const adminLink = document.getElementById("admin-link");
        if (adminLink) adminLink.style.display = "flex";
    }

    // 3. Logout Event
    document.getElementById("logout-btn")?.addEventListener("click", () => {
        Auth.clear();
        window.location.href = "/index.html";
    });

    // 4. Fetch Documents
    fetchDocuments();

    // 5. 2FA Setup Event
    document.getElementById("sidebar-2fa-btn")?.addEventListener("click", openTwofaSetup);
});

// ── Fetch Documents ──────────────────────────────────────────
async function fetchDocuments() {
    const tableWrap = document.getElementById("docs-table-wrap");
    const emptyMsg = document.getElementById("empty-msg");
    const loadingMsg = document.getElementById("loading-msg");

    const { ok, data } = await api("GET", "/documents/");

    loadingMsg.style.display = "none";

    if (!ok) {
        showToast("Failed to load documents", "error");
        return;
    }

    allDocuments = data.documents || [];

    updateStats();

    if (allDocuments.length === 0) {
        tableWrap.style.display = "none";
        emptyMsg.style.display = "block";
    } else {
        emptyMsg.style.display = "none";
        tableWrap.style.display = "block";
        renderDocuments(allDocuments);
    }
}

// ── Render Documents Table ───────────────────────────────────
function renderDocuments(docs) {
    const tbody = document.getElementById("docs-tbody");
    tbody.innerHTML = "";

    docs.forEach((doc, index) => {
        const row = document.createElement("tr");

        const statusHtml = doc.is_verified 
            ? `<span style="color:var(--success); font-weight:bold;">Verified</span>` 
            : `<span style="color:var(--accent);">Pending</span>`;

        const shortHash = doc.sha256_hash ? doc.sha256_hash.substring(0, 10) + "..." : "N/A";

        // Format Date
        const dateObj = new Date(doc.uploaded_at);
        const formattedDate = dateObj.toLocaleDateString();

        row.innerHTML = `
            <td>${index + 1}</td>
            <td style="font-weight:600;">${doc.original_filename}</td>
            <td>${doc.file_size_readable || doc.file_size + " bytes"}</td>
            <td><span class="badge">${doc.file_extension}</span></td>
            <td style="font-family:var(--font-mono); font-size:0.8rem;" title="${doc.sha256_hash}">${shortHash}</td>
            <td>${statusHtml}</td>
            <td>${formattedDate}</td>
            <td style="display:flex; gap:8px;">
                <button class="btn btn-primary" style="padding:4px 10px; font-size:0.8rem;" onclick="downloadDocument(${doc.id}, '${doc.original_filename}')">Download</button>
                <button class="btn btn-danger" style="padding:4px 10px; font-size:0.8rem;" onclick="promptDelete(${doc.id})">Delete</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// ── Filter Documents (Search) ───────────────────────────────
window.filterDocs = function(query) {
    query = query.toLowerCase().trim();
    if (!query) {
        renderDocuments(allDocuments);
        return;
    }
    
    const filtered = allDocuments.filter(doc => 
        doc.original_filename.toLowerCase().includes(query)
    );
    renderDocuments(filtered);
};

// ── Update Dashboard Stats ───────────────────────────────────
function updateStats() {
    const total = allDocuments.length;
    const verified = allDocuments.filter(d => d.is_verified).length;
    const encrypted = allDocuments.filter(d => d.is_encrypted).length;
    const signed = allDocuments.filter(d => d.has_signature).length;

    document.getElementById("stat-total").textContent = total;
    document.getElementById("stat-verified").textContent = verified;
    document.getElementById("stat-encrypted").textContent = encrypted;
    document.getElementById("stat-signed").textContent = signed;
}

// ── Download Document ────────────────────────────────────────
window.downloadDocument = async function(docId, filename) {
    showToast(`Decrypting and downloading ${filename}...`, "info");
    
    const token = Auth.getAccessToken();
    try {
        const response = await fetch(`/api/documents/${docId}/download`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            const data = await response.json();
            showToast(data.error || "Download failed", "error");
            return;
        }

        // Create a blob from the response to force download
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        
    } catch (err) {
        console.error(err);
        showToast("An error occurred during download.", "error");
    }
};

// ── Delete Document Logic ────────────────────────────────────
window.promptDelete = function(docId) {
    deleteDocId = docId;
    document.getElementById("delete-modal").style.display = "flex";
};

window.closeDeleteModal = function() {
    deleteDocId = null;
    document.getElementById("delete-modal").style.display = "none";
};

document.getElementById("confirm-delete-btn")?.addEventListener("click", async () => {
    if (!deleteDocId) return;
    
    const { ok, data } = await api("DELETE", `/documents/${deleteDocId}`);
    
    closeDeleteModal();

    if (ok) {
        showToast("Document deleted successfully", "success");
        fetchDocuments(); // Refresh table
    } else {
        showToast(data.error || "Failed to delete document", "error");
    }
});

// ── 2FA Setup Flow ───────────────────────────────────────────
async function openTwofaSetup() {
    const modal = document.getElementById("twofa-modal");
    const content = document.getElementById("twofa-modal-content");
    modal.style.display = "flex";
    content.innerHTML = `<p class="text-muted">Generating secure QR code...</p>`;

    const { ok, data } = await api("POST", "/2fa/setup");

    if (!ok) {
        content.innerHTML = `<p style="color:var(--danger)">${data.error || "Failed to setup 2FA"}</p>`;
        return;
    }

    const imgSrc = data.qr_code_b64 && data.qr_code_b64.startsWith('data:image') 
        ? data.qr_code_b64 
        : `data:image/png;base64,${data.qr_code_b64}`;

    content.innerHTML = `
        <div style="text-align:center; margin-bottom:15px; display:flex; justify-content:center;">
            <img src="${imgSrc}" alt="QR Code" style="width:180px; height:180px; object-fit:contain; border-radius:8px; border:2px solid var(--border); padding:10px; background:white;">
        </div>
        <p style="font-size:0.85rem; text-align:center; font-family:var(--font-mono); margin-bottom:15px;">${data.secret}</p>
        <p class="text-muted" style="font-size:0.85rem; text-align:center; margin-bottom:15px;">Scan this code using Google Authenticator, then enter the 6-digit code below to enable 2FA.</p>
        <div class="form-group">
            <input type="text" id="setup-totp-code" class="form-input text-mono" placeholder="000000" maxlength="6" style="text-align:center; letter-spacing:4px; font-size:1.1rem;">
        </div>
        <button class="btn btn-primary" style="width:100%" onclick="enableTwofa()">Verify & Enable</button>
    `;
}

window.closeTwofaModal = function() {
    document.getElementById("twofa-modal").style.display = "none";
};

window.enableTwofa = async function() {
    const code = document.getElementById("setup-totp-code").value.trim();
    if (code.length !== 6) {
        showToast("Please enter a valid 6-digit code.", "error");
        return;
    }

    const { ok, data } = await api("POST", "/2fa/enable", { code });

    if (ok) {
        showToast("Two-Factor Authentication enabled successfully!", "success");
        closeTwofaModal();
    } else {
        showToast(data.error || "Invalid code", "error");
    }
};