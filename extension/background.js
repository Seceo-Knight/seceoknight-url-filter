// =============================================================================
// SecEoKnight Security Extension — Background Service Worker
// =============================================================================
// Intercepts browser navigation events and checks each URL against the
// SecEoKnight AI phishing detection API. No latency on normal browsing —
// the check runs async AFTER the page starts loading.
//
// Server address is NOT hardcoded — it's read from chrome.storage.local
// (serverIP / serverPort), which the user sets from the extension popup.
// This means deploying to a different office/network with a different
// server IP never requires editing this file: just open the popup, type
// the new address, click Save. Falls back to DEFAULT_SERVER_IP/PORT below
// if nothing has been configured yet (fresh install).
// =============================================================================

const DEFAULT_SERVER_IP   = "192.168.1.63";
const DEFAULT_SERVER_PORT = 5001;

// Confidence threshold — above this the warning banner is shown
const WARN_THRESHOLD  = 0.80;   // 80% → yellow warning banner
const BLOCK_THRESHOLD = 0.95;   // 95% → red danger banner

// Cache checked URLs so the same page doesn't trigger repeated API calls
const urlCache   = new Map();    // url → { phishing, confidence, ts }
const CACHE_TTL  = 5 * 60 * 1000;  // 5 minutes

// Domains always considered safe — no need to check these
const WHITELIST = new Set([
  "google.com", "www.google.com",
  "microsoft.com", "www.microsoft.com",
  "github.com", "www.github.com",
  "apple.com", "www.apple.com",
  "amazon.com", "www.amazon.com",
  "cloudflare.com"
  // Note: LAN IPs (192.168.*, 10.*, 172.16-31.*) are already exempted by the
  // shouldSkip() regex check below — no need to whitelist the server IP here.
]);

// ── Server address (configurable, not hardcoded) ────────────────────────────

async function getApiBase() {
  const cfg = await chrome.storage.local.get(["serverIP", "serverPort"]);
  const ip   = cfg.serverIP   || DEFAULT_SERVER_IP;
  const port = cfg.serverPort || DEFAULT_SERVER_PORT;
  return `http://${ip}:${port}`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractHostname(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

function shouldSkip(url) {
  if (!url) return true;
  if (!url.startsWith("http://") && !url.startsWith("https://")) return true;
  const h = extractHostname(url);
  if (!h) return true;
  // Skip LAN/localhost addresses — these are internal and safe
  if (h === "localhost" || h === "127.0.0.1") return true;
  if (/^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[01])\./.test(h)) return true;
  // Skip whitelisted domains
  if (WHITELIST.has(h)) return true;
  return false;
}

function getCached(url) {
  const entry = urlCache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL) { urlCache.delete(url); return null; }
  return entry;
}

// ── Phishing API call ─────────────────────────────────────────────────────────

async function checkPhishing(url) {
  if (shouldSkip(url)) return null;

  const cached = getCached(url);
  if (cached) return cached;

  try {
    const apiBase = await getApiBase();
    const res = await fetch(`${apiBase}/predict/phishing`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
      signal:  AbortSignal.timeout(4000)   // 4s timeout — don't delay browsing
    });

    if (!res.ok) return null;
    const data = await res.json();

    const entry = {
      url,
      phishing:   data.phishing === true,
      confidence: typeof data.confidence === "number" ? data.confidence : 0,
      ts: Date.now()
    };

    urlCache.set(url, entry);
    return entry;

  } catch {
    // Server unreachable or timeout — fail open (don't block browsing)
    return null;
  }
}

// ── Send warning to the tab ───────────────────────────────────────────────────

async function sendWarningToTab(tabId, url, confidence) {
  const level = confidence >= BLOCK_THRESHOLD ? "danger" : "warning";

  // First try messaging the already-loaded content script
  try {
    await chrome.tabs.sendMessage(tabId, {
      type:       "SECEOKNIGHT_PHISHING_WARNING",
      url,
      confidence,
      level
    });
    return;
  } catch { /* content script not ready yet — fall through to scripting API */ }

  // Fallback: inject directly via scripting API
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: injectWarningBanner,
      args: [url, confidence, level]
    });
  } catch { /* tab navigated away or restricted page */ }
}

// Injected directly into the page when content script isn't ready
function injectWarningBanner(url, confidence, level) {
  if (document.getElementById("seceoknight-banner")) return;
  const pct  = Math.round(confidence * 100);
  const bg   = level === "danger" ? "#c0392b" : "#e67e22";
  const icon = level === "danger" ? "🚫" : "⚠️";
  const msg  = level === "danger"
    ? `DANGER: This page is very likely a phishing site (${pct}% confidence). Do NOT enter any information.`
    : `Warning: This page may be a phishing site (${pct}% confidence). Proceed with caution.`;

  const banner = document.createElement("div");
  banner.id = "seceoknight-banner";
  banner.style.cssText = [
    "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
    `background:${bg}`, "color:#fff", "font-family:Arial,sans-serif",
    "font-size:14px", "padding:10px 16px", "display:flex",
    "align-items:center", "gap:10px", "box-shadow:0 2px 8px rgba(0,0,0,0.5)"
  ].join(";");

  banner.innerHTML = `
    <span style="font-size:20px">${icon}</span>
    <span><strong>SecEoKnight:</strong> ${msg}</span>
    <button style="margin-left:auto;background:rgba(255,255,255,0.25);border:none;
      color:#fff;padding:4px 12px;cursor:pointer;border-radius:4px;font-size:13px"
      onclick="this.parentNode.remove()">Dismiss</button>
  `;
  document.documentElement.prepend(banner);
}

// ── Log event to server ───────────────────────────────────────────────────────

async function logEvent(url, confidence, tabId) {
  try {
    const apiBase = await getApiBase();
    const tab = await chrome.tabs.get(tabId).catch(() => null);
    await fetch(`${apiBase}/logs`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        timestamp:  Date.now() / 1000,
        url,
        host:       extractHostname(url) || url,
        blocked:    confidence >= BLOCK_THRESHOLD,
        event_type: "ai_phishing",
        confidence,
        client_ip:  "extension",
        tab_id:     tabId,
        title:      tab?.title || ""
      }),
      signal: AbortSignal.timeout(3000)
    });
  } catch { /* log failure is non-fatal */ }
}

// ── Navigation listener ───────────────────────────────────────────────────────

chrome.webNavigation.onCommitted.addListener(async (details) => {
  // Only check main frame (frameId 0), skip subframes/iframes
  if (details.frameId !== 0) return;

  // Only check real navigations — skip back/forward/reload to already-safe pages
  const userNav = ["link", "typed", "form_submit", "generated", "keyword"];
  if (!userNav.includes(details.transitionType)) return;

  const { tabId, url } = details;
  if (shouldSkip(url)) return;

  const result = await checkPhishing(url);
  if (!result || !result.phishing) return;
  if (result.confidence < WARN_THRESHOLD) return;

  // Show warning banner in the tab
  await sendWarningToTab(tabId, url, result.confidence);

  // Log the detection to the security server
  await logEvent(url, result.confidence, tabId);

  // Show browser notification for high-confidence threats
  if (result.confidence >= BLOCK_THRESHOLD) {
    chrome.notifications.create({
      type:    "basic",
      iconUrl: "icons/icon48.png",
      title:   "SecEoKnight — Phishing Detected",
      message: `High-confidence phishing site blocked: ${extractHostname(url)}`
    });
  }
});

// ── Download monitoring ───────────────────────────────────────────────────────

chrome.downloads.onCreated.addListener((item) => {
  // Log download events — malware scanning of file bytes requires the
  // /predict/malware endpoint which accepts image files via the dashboard
  console.log(`[SecEoKnight] Download: ${item.filename} from ${item.finalUrl || item.url}`);
});

// ── Storage: seed default server config on first install only ──────────────
// Important: onInstalled also fires on extension UPDATES, not just fresh
// installs. We must not clobber a server address the user already configured
// via the popup just because the extension was updated to a new version.

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason !== "install") return;
  const existing = await chrome.storage.local.get(["serverIP", "serverPort"]);
  if (!existing.serverIP) {
    await chrome.storage.local.set({
      serverIP:   DEFAULT_SERVER_IP,
      serverPort: DEFAULT_SERVER_PORT,
      enabled:    true
    });
  }
  console.log("[SecEoKnight] Extension installed and active.");
});
