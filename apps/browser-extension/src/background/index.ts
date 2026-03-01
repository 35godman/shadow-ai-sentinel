import { matchDomain, isAiApiEndpoint } from "@sentinel/ai-domain-registry";
import { scanText, redactText } from "@sentinel/regex-patterns";
import type {
  ExtensionConfig, AuditEvent, ShadowAiEvent, SensitivityLevel, PolicyAction, Detection
} from "@sentinel/shared-types";

// ============================================================
// STATE
// ============================================================

let config: ExtensionConfig = {
  orgId: "",
  apiKey: "",
  proxyEndpoint: "http://localhost:8080", // Default to local Docker proxy
  pollingIntervalMs: 60000,
  enabledDetectors: [],
  learningMode: false, // Enforce by default — learning mode is opt-in via proxy config
  aiDomainRegistryVersion: "1.0.0",
  regexPatternsVersion: "1.0.0",
};

// In-memory event buffer (batched sends to reduce network calls)
const eventBuffer: AuditEvent[] = [];
const shadowAiBuffer: ShadowAiEvent[] = [];
const FLUSH_INTERVAL_MS = 10000;

// ============================================================
// INITIALIZATION
// ============================================================

chrome.runtime.onInstalled.addListener(async () => {
  console.log("[Sentinel] Extension installed. Loading config...");
  await loadConfig();
  startEventFlush();
  startConfigPolling();
});

chrome.runtime.onStartup.addListener(async () => {
  await loadConfig();
  startEventFlush();
  startConfigPolling();
});

async function loadConfig() {
  const stored = await chrome.storage.local.get("sentinel_config");
  if (stored.sentinel_config) {
    config = { ...config, ...stored.sentinel_config };
  }
}

async function saveConfig() {
  await chrome.storage.local.set({ sentinel_config: config });
  // Broadcast updated config to all content scripts so they apply it immediately
  // without waiting for the next page load.
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      if (tab.id) {
        chrome.tabs.sendMessage(tab.id, { type: "CONFIG_UPDATE", config }).catch(() => {
          // Tab may not have a content script — ignore silently
        });
      }
    }
  });
}

// ============================================================
// SHADOW AI TRACKING
// Track every visit to an AI tool domain
// ============================================================

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;

  const aiTool = matchDomain(tab.url);
  if (!aiTool) return;

  const event: ShadowAiEvent = {
    id: crypto.randomUUID(),
    orgId: config.orgId,
    userId: "", // Set from config or auth
    userEmail: "",
    domain: aiTool.domain,
    aiToolName: aiTool.name,
    category: aiTool.category,
    riskLevel: aiTool.riskLevel,
    action: "visited",
    timestamp: new Date().toISOString(),
    browserMeta: {
      browser: "chrome",
      version: navigator.userAgent,
      os: navigator.platform,
      managed: false,
      extensionVersion: chrome.runtime.getManifest().version,
    },
  };

  shadowAiBuffer.push(event);

  // Show badge indicator
  chrome.action.setBadgeText({ text: "AI", tabId });
  chrome.action.setBadgeBackgroundColor({
    color: aiTool.riskLevel === "RISKY" ? "#E74C3C"
      : aiTool.riskLevel === "CAUTION" ? "#F39C12"
      : "#27AE60",
    tabId,
  });
});

// ============================================================
// CONTENT SCRIPT MESSAGING
// Receives scan requests from content scripts
// ============================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAN_CONTENT") {
    handleScanRequest(message, sender).then(sendResponse);
    return true; // Indicates async response
  }

  if (message.type === "GET_CONFIG") {
    sendResponse(config);
    return false;
  }

  if (message.type === "UPDATE_CONFIG") {
    config = { ...config, ...message.config };
    saveConfig();
    sendResponse({ success: true });
    return false;
  }

  if (message.type === "GET_RECENT_EVENTS") {
    getRecentEvents().then(sendResponse);
    return true;
  }
});

async function handleScanRequest(
  message: { content: string; targetDomain: string; targetUrl: string; contentType: string },
  sender: chrome.runtime.MessageSender
): Promise<{ action: PolicyAction; detections: Partial<Detection>[]; userMessage?: string; redactedContent?: string }> {

  const { content, targetDomain, targetUrl, contentType } = message;

  // Step 1: Local regex scan (instant, <5ms)
  const scanResult = scanText(content, {
    enabledTypes: config.enabledDetectors.length > 0 ? config.enabledDetectors : undefined,
  });

  // Step 2: If CRITICAL match, block immediately (no server round-trip)
  if (scanResult.combinedRiskScore === "CRITICAL" && !config.learningMode) {
    logAuditEvent("block", scanResult.detections, targetDomain);
    return {
      action: "BLOCK",
      detections: scanResult.detections.map(d => ({
        entityType: d.entityType,
        confidence: d.confidence,
        contextRiskScore: d.contextRiskScore,
        redactedText: d.redactedText,
        startOffset: d.startOffset,
        endOffset: d.endOffset,
      })),
      userMessage: `Blocked: ${scanResult.detections.map(d => d.entityType).join(", ")} detected. This content contains sensitive data that cannot be sent to AI tools.`,
    };
  }

  // Step 3: If detections exist, send to proxy for deep ML scan (if configured)
  if (scanResult.detections.length > 0 && config.proxyEndpoint) {
    try {
      const proxyResult = await sendToProxy(content, targetDomain, targetUrl, contentType);
      if (proxyResult) {
        return proxyResult;
      }
    } catch (err) {
      console.warn("[Sentinel] Proxy unavailable, using local-only scan:", err);
    }
  }

  // Step 4: Apply local-only policy
  const action = config.learningMode ? "LOG" as PolicyAction : scanResult.recommendedAction;

  if (scanResult.detections.length > 0) {
    logAuditEvent(action === "BLOCK" ? "block" : action === "REDACT" ? "redact" : "scan", scanResult.detections, targetDomain);
  }

  const userMessage = scanResult.detections.length > 0
    ? config.learningMode
      ? `Learning Mode: ${scanResult.detections.length} sensitive item(s) detected (${scanResult.detections.map(d => d.entityType).join(", ")}). No action taken.`
      : `${action}: ${scanResult.detections.map(d => d.entityType).join(", ")} detected.`
    : undefined;

  return {
    action,
    detections: scanResult.detections.map(d => ({
      entityType: d.entityType,
      confidence: d.confidence,
      contextRiskScore: d.contextRiskScore,
      redactedText: d.redactedText,
      startOffset: d.startOffset,
      endOffset: d.endOffset,
    })),
    userMessage,
    // Include redacted content so the content script can insert it instead of original
    redactedContent: action === "REDACT" && scanResult.detections.length > 0
      ? redactText(content, scanResult.detections)
      : undefined,
  };
}

// ============================================================
// PROXY COMMUNICATION
// ============================================================

async function sendToProxy(
  content: string,
  targetDomain: string,
  targetUrl: string,
  contentType: string
): Promise<{ action: PolicyAction; detections: Partial<Detection>[]; userMessage?: string; redactedContent?: string } | null> {
  // Only require proxyEndpoint — apiKey is optional (proxy allows unauthenticated
  // requests in dev mode when API_KEY env is not set).
  if (!config.proxyEndpoint) return null;

  const response = await fetch(`${config.proxyEndpoint}/api/v1/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${config.apiKey}`,
      "X-Org-Id": config.orgId,
    },
    body: JSON.stringify({
      content,
      contentType,
      targetDomain,
      targetUrl,
      timestamp: new Date().toISOString(),
    }),
    signal: AbortSignal.timeout(5000), // 5s timeout — don't slow the user down
  });

  if (!response.ok) return null;
  return response.json();
}

// ============================================================
// AUDIT LOGGING
// ============================================================

function logAuditEvent(eventType: AuditEvent["eventType"], detections: Detection[], aiTool: string) {
  const event: AuditEvent = {
    id: crypto.randomUUID(),
    orgId: config.orgId,
    userId: "",
    userEmail: "",
    eventType,
    aiTool,
    entityTypesDetected: detections.map(d => d.entityType),
    sensitivityLevel: detections.length > 0
      ? (detections.reduce((max, d) => {
          const order: Record<SensitivityLevel, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
          return order[d.contextRiskScore] > order[max] ? d.contextRiskScore : max;
        }, "LOW" as SensitivityLevel))
      : "LOW",
    actionTaken: detections.length > 0 ? (eventType === "block" ? "BLOCK" : eventType === "redact" ? "REDACT" : "WARN") : "LOG",
    timestamp: new Date().toISOString(),
    metadata: {},
  };

  eventBuffer.push(event);

  // Also store locally for popup display
  storeRecentEvent(event);
}

async function storeRecentEvent(event: AuditEvent) {
  const stored = await chrome.storage.local.get("recent_events");
  const events: AuditEvent[] = stored.recent_events || [];
  events.unshift(event);
  // Keep last 100 events
  await chrome.storage.local.set({ recent_events: events.slice(0, 100) });
}

async function getRecentEvents(): Promise<AuditEvent[]> {
  const stored = await chrome.storage.local.get("recent_events");
  return stored.recent_events || [];
}

// ============================================================
// BATCH EVENT FLUSH
// ============================================================

function startEventFlush() {
  chrome.alarms.create("flush-events", { periodInMinutes: FLUSH_INTERVAL_MS / 60000 });
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "flush-events") flushEvents();
    if (alarm.name === "poll-config") pollConfig();
  });
}

async function flushEvents() {
  if (eventBuffer.length === 0 && shadowAiBuffer.length === 0) return;
  if (!config.proxyEndpoint || !config.apiKey) return;

  const auditBatch = eventBuffer.splice(0, eventBuffer.length);
  const shadowBatch = shadowAiBuffer.splice(0, shadowAiBuffer.length);

  try {
    await fetch(`${config.proxyEndpoint}/api/v1/events/batch`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${config.apiKey}`,
        "X-Org-Id": config.orgId,
      },
      body: JSON.stringify({ auditEvents: auditBatch, shadowAiEvents: shadowBatch }),
      signal: AbortSignal.timeout(10000),
    });
  } catch (err) {
    // Put events back in buffer for retry
    eventBuffer.unshift(...auditBatch);
    shadowAiBuffer.unshift(...shadowBatch);
    console.warn("[Sentinel] Failed to flush events:", err);
  }
}

// ============================================================
// CONFIG POLLING
// ============================================================

function startConfigPolling() {
  chrome.alarms.create("poll-config", { periodInMinutes: config.pollingIntervalMs / 60000 });
}

async function pollConfig() {
  if (!config.proxyEndpoint || !config.apiKey) return;

  try {
    const response = await fetch(`${config.proxyEndpoint}/api/v1/config`, {
      headers: {
        "Authorization": `Bearer ${config.apiKey}`,
        "X-Org-Id": config.orgId,
      },
      signal: AbortSignal.timeout(5000),
    });

    if (response.ok) {
      const serverConfig = await response.json();
      config = { ...config, ...serverConfig };
      await saveConfig();
    }
  } catch (err) {
    console.warn("[Sentinel] Config poll failed:", err);
  }
}
