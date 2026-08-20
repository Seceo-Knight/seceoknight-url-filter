// =============================================================================
// SecEoKnight Extension — Popup Script
// =============================================================================
// Server address is stored in chrome.storage.local (serverIP / serverPort),
// not hardcoded here. This lets anyone change which server the extension
// talks to directly from this popup — no code editing, no reloading the
// extension from a folder, works for deploying to a different office/network
// with zero technical steps.
// =============================================================================

const DEFAULT_SERVER_IP   = "192.168.1.63";
const DEFAULT_SERVER_PORT = 5001;

async function getServerConfig() {
  const cfg = await chrome.storage.local.get(["serverIP", "serverPort"]);
  return {
    serverIP:   cfg.serverIP   || DEFAULT_SERVER_IP,
    serverPort: cfg.serverPort || DEFAULT_SERVER_PORT
  };
}

async function loadStatus() {
  const loading = document.getElementById("loading");
  const content = document.getElementById("content");

  const { serverIP, serverPort } = await getServerConfig();
  const apiBase = `http://${serverIP}:${serverPort}`;

  try {
    // Fetch server health
    const healthRes = await fetch(`${apiBase}/health`, {
      signal: AbortSignal.timeout(4000)
    });
    const health = await healthRes.json();

    // Fetch stats
    const statsRes = await fetch(`${apiBase}/api/stats`, {
      signal: AbortSignal.timeout(4000)
    });
    const stats = await statsRes.json();

    // Server is up
    document.getElementById("server-dot").className         = "dot green";
    document.getElementById("server-status-text").textContent = "Server Online";
    document.getElementById("server-status-sub").textContent  = health.status || "healthy";

    // AI model status
    const ai = health.ai || {};
    const phishing = ai.phishing_model === "loaded" ? "✓ phishing" : "✗ phishing";
    const malware  = ai.malware_models
      ? Object.values(ai.malware_models).every(v => v === "loaded") ? "✓ malware" : "~ malware"
      : "✗ malware";
    document.getElementById("info-models").textContent = `${phishing}, ${malware}`;

    // Stats — field names match server/database.py's get_stats()
    document.getElementById("stat-blocks").textContent =
      (stats.total_blocked ?? 0).toLocaleString();
    document.getElementById("stat-ai").textContent =
      ((stats.ai_phishing ?? 0) + (stats.ai_malware ?? 0)).toLocaleString();

  } catch {
    // Server unreachable
    document.getElementById("server-dot").className          = "dot red";
    document.getElementById("server-status-text").textContent  = "Server Unreachable";
    document.getElementById("server-status-sub").textContent   = `Cannot connect to ${apiBase}`;
    document.getElementById("info-models").textContent         = "unknown";
    document.getElementById("stat-blocks").textContent         = "—";
    document.getElementById("stat-ai").textContent              = "—";
  }

  document.getElementById("info-ip").textContent   = serverIP;
  document.getElementById("info-port").textContent = serverPort;

  loading.style.display = "none";
  content.style.display = "block";
}

// ── Settings panel (edit server address) ─────────────────────────────────────

function ipOrHostnameLooksValid(value) {
  if (!value) return false;
  // Accept a dotted IPv4 address or a bare hostname (letters/digits/dots/hyphens)
  const ipv4     = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  const hostname = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,62})(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}))*$/;
  return ipv4.test(value) || hostname.test(value);
}

async function initSettingsPanel() {
  const { serverIP, serverPort } = await getServerConfig();
  const ipInput   = document.getElementById("settings-ip");
  const portInput = document.getElementById("settings-port");
  const saveBtn   = document.getElementById("settings-save");
  const statusEl  = document.getElementById("settings-status");
  const toggle    = document.getElementById("settings-toggle");
  const panel     = document.getElementById("settings-panel");

  ipInput.value   = serverIP;
  portInput.value = serverPort;

  toggle.addEventListener("click", () => {
    const isOpen = panel.style.display === "block";
    panel.style.display = isOpen ? "none" : "block";
    toggle.textContent  = isOpen ? "⚙ Change Server ▾" : "⚙ Change Server ▴";
  });

  saveBtn.addEventListener("click", async () => {
    const newIp   = ipInput.value.trim();
    const newPort = parseInt(portInput.value.trim(), 10);

    if (!ipOrHostnameLooksValid(newIp)) {
      statusEl.textContent = "Enter a valid IP address or hostname (e.g. 192.168.1.63)";
      statusEl.style.color = "#e74c3c";
      return;
    }
    if (!newPort || newPort < 1 || newPort > 65535) {
      statusEl.textContent = "Enter a valid port number (e.g. 5001)";
      statusEl.style.color = "#e74c3c";
      return;
    }

    await chrome.storage.local.set({ serverIP: newIp, serverPort: newPort });
    statusEl.textContent = "Saved — reconnecting…";
    statusEl.style.color = "#2ecc71";

    // Re-check status against the newly saved server immediately
    await loadStatus();
    setTimeout(() => { statusEl.textContent = ""; }, 3000);
  });
}

loadStatus();
initSettingsPanel();
