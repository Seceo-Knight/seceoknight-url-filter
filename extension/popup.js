// =============================================================================
// SecEoKnight Extension — Popup Script
// =============================================================================

const API_BASE = "http://192.168.1.63:5001";

async function loadStatus() {
  const loading = document.getElementById("loading");
  const content = document.getElementById("content");

  try {
    // Fetch server health
    const healthRes = await fetch(`${API_BASE}/health`, {
      signal: AbortSignal.timeout(4000)
    });
    const health = await healthRes.json();

    // Fetch stats
    const statsRes = await fetch(`${API_BASE}/api/stats`, {
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

    // Stats
    document.getElementById("stat-blocks").textContent =
      (stats.blocked_requests ?? stats.total_blocked ?? "—").toLocaleString();
    document.getElementById("stat-ai").textContent =
      (stats.ai_detections ?? "—").toLocaleString();

  } catch {
    // Server unreachable
    document.getElementById("server-dot").className          = "dot red";
    document.getElementById("server-status-text").textContent  = "Server Unreachable";
    document.getElementById("server-status-sub").textContent   = `Cannot connect to ${API_BASE}`;
    document.getElementById("info-models").textContent         = "unknown";
    document.getElementById("stat-blocks").textContent         = "—";
    document.getElementById("stat-ai").textContent             = "—";
  }

  // Read server IP from storage
  chrome.storage.local.get(["serverIP", "serverPort"], (cfg) => {
    document.getElementById("info-ip").textContent   = cfg.serverIP   || "192.168.1.189";
    document.getElementById("info-port").textContent = cfg.serverPort || "5001";
  });

  loading.style.display = "none";
  content.style.display = "block";
}

loadStatus();
