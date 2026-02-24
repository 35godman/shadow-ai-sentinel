import { matchDomain } from "@sentinel/ai-domain-registry";
import type { AuditEvent, AiToolEntry } from "@sentinel/shared-types";

// ============================================================
// POPUP UI LOGIC
// ============================================================

document.addEventListener("DOMContentLoaded", async () => {
  await loadCurrentPageInfo();
  await loadRecentEvents();
  await loadConfig();
  setupToggle();
  checkProxyConnection();
});

// --- Current Page Info ---
async function loadCurrentPageInfo() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;

  const aiTool = matchDomain(tab.url);
  const section = document.getElementById("current-page-section")!;
  const nameEl = document.getElementById("page-name")!;
  const riskEl = document.getElementById("page-risk")!;
  const iconEl = document.getElementById("page-risk-icon")!;

  if (aiTool) {
    section.style.display = "block";
    nameEl.textContent = aiTool.name;
    riskEl.textContent = `Risk: ${aiTool.riskLevel}${aiTool.trainsOnUserData ? " • Trains on data" : ""}`;
    iconEl.className = `page-icon ${aiTool.riskLevel.toLowerCase()}`;
    iconEl.textContent = aiTool.riskLevel === "RISKY" ? "🔴" : aiTool.riskLevel === "CAUTION" ? "🟡" : "🟢";
  }
}

// --- Recent Events ---
async function loadRecentEvents() {
  const events: AuditEvent[] = await chrome.runtime.sendMessage({ type: "GET_RECENT_EVENTS" });
  const container = document.getElementById("recent-events")!;

  if (!events || events.length === 0) return;

  const today = new Date().toDateString();
  const todayEvents = events.filter(e => new Date(e.timestamp).toDateString() === today);

  // Update stats
  document.getElementById("total-scans")!.textContent = String(todayEvents.length);
  document.getElementById("total-warnings")!.textContent = String(
    todayEvents.filter(e => e.actionTaken === "WARN").length
  );
  document.getElementById("total-blocks")!.textContent = String(
    todayEvents.filter(e => e.actionTaken === "BLOCK").length
  );

  // Render event list (last 10)
  const recentSlice = events.slice(0, 10);
  container.innerHTML = recentSlice.map(event => {
    const time = formatTime(event.timestamp);
    const icon = event.actionTaken === "BLOCK" ? "🚫"
      : event.actionTaken === "REDACT" ? "✏️"
      : event.actionTaken === "WARN" ? "⚠️"
      : "📝";
    const actionClass = event.actionTaken.toLowerCase();

    return `
      <div class="event-item">
        <span class="event-icon">${icon}</span>
        <div class="event-details">
          <div class="event-type">${event.entityTypesDetected.join(", ") || "Scan"}</div>
          <div class="event-meta">${event.aiTool || "Unknown"} • ${time}</div>
        </div>
        <span class="event-action ${actionClass}">${event.actionTaken}</span>
      </div>
    `;
  }).join("");
}

// --- Config ---
async function loadConfig() {
  const config = await chrome.runtime.sendMessage({ type: "GET_CONFIG" });
  if (config) {
    const toggle = document.getElementById("learning-mode-toggle") as HTMLInputElement;
    toggle.checked = config.learningMode;
  }
}

function setupToggle() {
  const toggle = document.getElementById("learning-mode-toggle") as HTMLInputElement;
  toggle.addEventListener("change", () => {
    chrome.runtime.sendMessage({
      type: "UPDATE_CONFIG",
      config: { learningMode: toggle.checked },
    });
  });
}

// --- Proxy Connection Check ---
async function checkProxyConnection() {
  const config = await chrome.runtime.sendMessage({ type: "GET_CONFIG" });
  const statusEl = document.getElementById("connection-status")!;

  if (!config?.proxyEndpoint || !config?.apiKey) {
    statusEl.innerHTML = '<span class="conn-dot conn-disconnected"></span> Not configured';
    return;
  }

  try {
    const response = await fetch(`${config.proxyEndpoint}/api/v1/health`, {
      signal: AbortSignal.timeout(3000),
    });
    if (response.ok) {
      statusEl.innerHTML = '<span class="conn-dot conn-connected"></span> Connected to proxy';
    } else {
      statusEl.innerHTML = '<span class="conn-dot conn-disconnected"></span> Proxy unreachable';
    }
  } catch {
    statusEl.innerHTML = '<span class="conn-dot conn-disconnected"></span> Proxy offline';
  }
}

// --- Utilities ---
function formatTime(isoString: string): string {
  const date = new Date(isoString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMin = Math.floor(diffMs / 60000);

  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffMin < 1440) return `${Math.floor(diffMin / 60)}h ago`;
  return date.toLocaleDateString();
}
