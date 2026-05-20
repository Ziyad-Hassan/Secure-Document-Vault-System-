/* ================================================
   Secure Document Vault — Auth Page Logic
   Handles: Login, Register, 2FA, Password Strength, OAuth
   ================================================ */

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.closest("html");
  const isRegister = !!document.getElementById("register-form");
  const isLogin    = !!document.getElementById("login-form");

  // Redirect if already logged in
  if (Auth.isLoggedIn()) {
    window.location.href = "/pages/dashboard.html";
    return;
  }

  if (isLogin)    initLoginPage();
  if (isRegister) initRegisterPage();
});


// ══════════════════════════════════════════════════
//  LOGIN PAGE
// ══════════════════════════════════════════════════

function initLoginPage() {
  const form     = document.getElementById("login-form");
  const btn      = document.getElementById("login-btn");
  const togglePw = document.getElementById("toggle-pw");
  const pwInput  = document.getElementById("password");

  // 2FA section
  const twofaSection = document.getElementById("twofa-section");
  const loginSection = document.getElementById("login-form-section");
  const twofaForm    = document.getElementById("twofa-form");
  const twofaBtn     = document.getElementById("twofa-btn");
  const backBtn      = document.getElementById("back-to-login");

  // OAuth Buttons
  const githubBtn    = document.getElementById("github-btn");

  let partialToken = null;

  // Toggle password visibility
  togglePw?.addEventListener("click", () => {
    const type = pwInput.type === "password" ? "text" : "password";
    pwInput.type = type;
    togglePw.textContent = type === "password" ? "👁" : "🙈";
  });

  // ── Login form submit ──────────────────────────
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearAlert("alert-area");

    const identifier = document.getElementById("identifier").value.trim();
    const password   = document.getElementById("password").value;

    if (!identifier || !password) {
      showAlert("alert-area", "Please fill in all fields.", "error");
      return;
    }

    setLoading(btn, true);

    const { ok, data } = await api("POST", "/auth/login", { identifier, password }, false);

    setLoading(btn, false);

    if (!ok) {
      showAlert("alert-area", data.error || "Login failed. Check your credentials.", "error");
      return;
    }

    // ── 2FA required ────────────────────────────
    if (data.requires_2fa) {
      partialToken = data.partial_token;
      loginSection.style.display = "none";
      twofaSection.style.display = "block";
      showAlert("alert-area", "Enter your authenticator code to continue.", "info");
      document.getElementById("totp-code")?.focus();
      return;
    }

    // ── Success: store tokens and redirect ───────
    handleLoginSuccess(data);
  });

  // ── 2FA form submit ────────────────────────────
  twofaForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearAlert("alert-area");

    const code = document.getElementById("totp-code").value.trim();
    if (code.length !== 6) {
      showAlert("alert-area", "Please enter a valid 6-digit code.", "error");
      return;
    }

    setLoading(twofaBtn, true);
    const { ok, data } = await api("POST", "/2fa/verify-login", {
      partial_token: partialToken,
      code,
    }, false);
    setLoading(twofaBtn, false);

    if (!ok) {
      showAlert("alert-area", data.error || "Invalid 2FA code.", "error");
      return;
    }

    handleLoginSuccess(data);
  });

  // Back to login
  backBtn?.addEventListener("click", (e) => {
    e.preventDefault();
    twofaSection.style.display = "none";
    loginSection.style.display = "block";
    clearAlert("alert-area");
    partialToken = null;
  });

  // ── GitHub OAuth Logic (Direct Redirect) ─────────
  githubBtn?.addEventListener("click", (e) => {
    e.preventDefault();
    // تحويل مباشر في نفس الصفحة
    window.location.href = "/api/oauth/login";
  });
}

function handleLoginSuccess(data) {
  Auth.setTokens(data.access_token, data.refresh_token);
  Auth.setUser(data.user);
  showToast(`Welcome back, ${data.user.username}!`, "success");

  // Role-based redirect
  const role = data.user.role;
  if (role === "admin")   window.location.href = "/pages/admin.html";
  else                    window.location.href = "/pages/dashboard.html";
}


// ══════════════════════════════════════════════════
//  REGISTER PAGE
// ══════════════════════════════════════════════════

function initRegisterPage() {
  const form           = document.getElementById("register-form");
  const btn            = document.getElementById("register-btn");
  const pwInput        = document.getElementById("password");
  const confirmInput   = document.getElementById("confirm-password");
  const togglePw       = document.getElementById("toggle-pw");
  const toggleConfirm  = document.getElementById("toggle-confirm");
  const matchMsg       = document.getElementById("match-msg");

  // ── Toggle password visibility ─────────────────
  togglePw?.addEventListener("click", () => {
    const t = pwInput.type === "password" ? "text" : "password";
    pwInput.type = t;
    togglePw.textContent = t === "password" ? "👁" : "🙈";
  });
  toggleConfirm?.addEventListener("click", () => {
    const t = confirmInput.type === "password" ? "text" : "password";
    confirmInput.type = t;
    toggleConfirm.textContent = t === "password" ? "👁" : "🙈";
  });

  // ── Real-time password strength ────────────────
  let strengthTimer = null;
  pwInput?.addEventListener("input", () => {
    clearTimeout(strengthTimer);
    strengthTimer = setTimeout(() => checkPasswordStrength(pwInput.value), 300);
    checkPasswordMatch();
  });
  confirmInput?.addEventListener("input", checkPasswordMatch);

  // ── Register form submit ───────────────────────
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearAlert("alert-area");

    const username         = document.getElementById("username").value.trim();
    const email            = document.getElementById("email").value.trim();
    const password         = pwInput.value;
    const confirm_password = confirmInput.value;

    if (!username || !email || !password || !confirm_password) {
      showAlert("alert-area", "All fields are required.", "error");
      return;
    }
    if (password !== confirm_password) {
      showAlert("alert-area", "Passwords do not match.", "error");
      return;
    }

    setLoading(btn, true);
    const { ok, data } = await api(
      "POST", "/auth/register",
      { username, email, password, confirm_password },
      false
    );
    setLoading(btn, false);

    if (!ok) {
      let msg = data.error || "Registration failed.";
      if (data.details && data.details.length) {
        msg += `<ul style="margin-top:8px;padding-left:18px;">${data.details.map(d => `<li>${d}</li>`).join("")}</ul>`;
      }
      showAlert("alert-area", msg, "error");
      return;
    }

    showAlert("alert-area", "Account created! Redirecting to login…", "success");
    setTimeout(() => window.location.href = "/", 1800);
  });
}

async function checkPasswordStrength(password) {
  const bar    = document.getElementById("strength-bar");
  const label  = document.getElementById("strength-label");
  const text   = document.getElementById("strength-text");
  const list   = document.getElementById("policy-list");

  if (!password) {
    bar.style.display = label.style.display = list.style.display = "none";
    return;
  }

  bar.style.display = label.style.display = list.style.display = "block";

  try {
    const { ok, data } = await api("POST", "/auth/password-strength", { password }, false);
    if (!ok) return;

    // Score segments (0–100 → 0–4 filled)
    const filled = Math.ceil(data.score / 25);
    const colors = { Weak: "#e76f51", Fair: "#e9c46a", Good: "#2a9d8f", Strong: "#57cc99" };
    const segs = [
      document.getElementById("seg1"),
      document.getElementById("seg2"),
      document.getElementById("seg3"),
      document.getElementById("seg4"),
    ];
    segs.forEach((s, i) => {
      s.style.background = i < filled ? (colors[data.label] || "#2a9d8f") : "var(--border)";
    });

    text.textContent = data.label;
    text.style.color = colors[data.label] || "var(--text-muted)";

    // Policy checklist
    const checks = data.checks || {};
    const items = {
      "p-len":  checks.length_8,
      "p-upper": checks.uppercase,
      "p-lower": checks.lowercase,
      "p-digit": checks.digit,
      "p-spec":  checks.special,
    };
    Object.entries(items).forEach(([id, passed]) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.style.color = passed ? "var(--success)" : "var(--text-muted)";
      el.textContent = el.textContent.replace(/^[○✓]/, passed ? "✓" : "○");
    });

  } catch (err) {
    console.warn("Strength check failed:", err);
  }
}

function checkPasswordMatch() {
  const pw  = document.getElementById("password")?.value;
  const cpw = document.getElementById("confirm-password")?.value;
  const msg = document.getElementById("match-msg");
  if (!msg || !cpw) return;

  if (cpw.length === 0) { msg.textContent = ""; return; }

  if (pw === cpw) {
    msg.textContent = "✓ Passwords match";
    msg.style.color = "var(--success)";
  } else {
    msg.textContent = "✕ Passwords do not match";
    msg.style.color = "var(--danger)";
  }
}