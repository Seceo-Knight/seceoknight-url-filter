// =============================================================================
// SecEoKnight Security Extension — Content Script
// =============================================================================
// Injected into every page. Listens for phishing warning messages from the
// background service worker and displays a warning banner.
// =============================================================================

chrome.runtime.onMessage.addListener((message) => {
  if (message.type !== "SECEOKNIGHT_PHISHING_WARNING") return;

  // Don't stack multiple banners
  if (document.getElementById("seceoknight-banner")) return;

  const { confidence, level } = message;
  const pct  = Math.round(confidence * 100);
  const isDanger = level === "danger";
  const bg   = isDanger ? "#c0392b" : "#e67e22";
  const icon = isDanger ? "🚫" : "⚠️";
  const headline = isDanger ? "PHISHING SITE DETECTED" : "Potential Phishing Site";
  const body = isDanger
    ? `This page has been identified as a phishing site with ${pct}% confidence. Do <strong>NOT</strong> enter any passwords, credit card numbers, or personal information.`
    : `This page shows signs of phishing (${pct}% confidence). Verify the URL carefully before entering any information.`;

  // Inject styles
  const style = document.createElement("style");
  style.textContent = `
    #seceoknight-banner {
      position: fixed;
      top: 0; left: 0; right: 0;
      z-index: 2147483647;
      background: ${bg};
      color: #fff;
      font-family: Arial, Helvetica, sans-serif;
      font-size: 14px;
      line-height: 1.4;
      padding: 12px 16px;
      display: flex;
      align-items: flex-start;
      gap: 12px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.5);
      box-sizing: border-box;
    }
    #seceoknight-banner .sk-icon  { font-size: 22px; flex-shrink: 0; margin-top: 1px; }
    #seceoknight-banner .sk-body  { flex: 1; }
    #seceoknight-banner .sk-title { font-weight: bold; font-size: 15px; margin-bottom: 2px; }
    #seceoknight-banner .sk-text  { opacity: 0.95; }
    #seceoknight-banner .sk-close {
      flex-shrink: 0;
      background: rgba(255,255,255,0.2);
      border: none;
      color: #fff;
      padding: 5px 14px;
      cursor: pointer;
      border-radius: 4px;
      font-size: 13px;
      margin-top: 2px;
    }
    #seceoknight-banner .sk-close:hover { background: rgba(255,255,255,0.35); }
  `;
  document.head.appendChild(style);

  // Build banner
  const banner = document.createElement("div");
  banner.id = "seceoknight-banner";
  banner.innerHTML = `
    <span class="sk-icon">${icon}</span>
    <div class="sk-body">
      <div class="sk-title">SecEoKnight — ${headline}</div>
      <div class="sk-text">${body}</div>
    </div>
    <button class="sk-close" id="sk-dismiss-btn">Dismiss</button>
  `;

  // Insert before anything else on the page
  if (document.documentElement) {
    document.documentElement.prepend(banner);
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      document.documentElement.prepend(banner);
    });
  }

  document.getElementById("sk-dismiss-btn")?.addEventListener("click", () => {
    banner.remove();
    style.remove();
  });
});
