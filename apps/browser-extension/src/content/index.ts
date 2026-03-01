// ============================================================
// Shadow AI Sentinel — Content Script
// Injected into AI tool pages (ChatGPT, Claude, Gemini, etc.)
// Monitors: paste, input, upload, form submit
// ============================================================

import { scanText, redactText } from "@sentinel/regex-patterns";
import type { PolicyAction, Detection } from "@sentinel/shared-types";

// --- State ---
let isEnabled = true;
let learningMode = false; // Enforce by default — matches proxy and background defaults
let lastScanResult: { action: PolicyAction; detections: Partial<Detection>[] } | null = null;

// --- Load config from background on init ---
chrome.runtime.sendMessage({ type: "GET_CONFIG" }, (config) => {
  if (config) {
    isEnabled = true;
    learningMode = config.learningMode ?? false;
  }
});

// --- Listen for live config updates pushed from background ---
// Background calls saveConfig() → broadcasts CONFIG_UPDATE to all content scripts.
// This lets learning mode toggles take effect immediately without page reload.
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "CONFIG_UPDATE" && message.config) {
    learningMode = message.config.learningMode ?? false;
  }
});

// ============================================================
// PASTE INTERCEPTION
// The #1 vector: users copy-paste sensitive data into AI prompts
// ============================================================

document.addEventListener("paste", async (event: ClipboardEvent) => {
  if (!isEnabled) return;

  const pastedText = event.clipboardData?.getData("text/plain");
  if (!pastedText || pastedText.length < 5) return; // Ignore trivial pastes

  const result = await scanContent(pastedText, "paste");

  if (result.action === "BLOCK") {
    event.preventDefault();
    event.stopImmediatePropagation();
    showUserNotification(result.userMessage || "Paste blocked: sensitive data detected", "error");
    return;
  }

  if (result.action === "WARN") {
    showUserNotification(result.userMessage || "Warning: sensitive data detected in paste", "warning");
  }

  if (result.action === "REDACT" && result.redactedContent) {
    event.preventDefault();
    event.stopImmediatePropagation();
    // Insert redacted content instead
    const target = event.target as HTMLElement;
    if (target instanceof HTMLTextAreaElement || target instanceof HTMLInputElement) {
      const start = target.selectionStart || 0;
      const end = target.selectionEnd || 0;
      const current = target.value;
      target.value = current.substring(0, start) + result.redactedContent + current.substring(end);
      // Trigger input event so the AI tool's framework picks up the change
      target.dispatchEvent(new Event("input", { bubbles: true }));
    } else if (target.contentEditable === "true") {
      document.execCommand("insertText", false, result.redactedContent);
    }
    showUserNotification("Sensitive data was automatically redacted before sending", "info");
  }
}, true); // Capture phase to intercept before the AI tool's handler

// ============================================================
// INPUT MONITORING
// Detects typing of sensitive data (e.g., manually typing an SSN)
// Debounced to avoid excessive scanning
// ============================================================

let inputDebounceTimer: ReturnType<typeof setTimeout> | null = null;
const INPUT_DEBOUNCE_MS = 1500; // Scan after 1.5s of no typing

document.addEventListener("input", (event: Event) => {
  if (!isEnabled) return;

  const target = event.target as HTMLElement;
  if (!isPromptInput(target)) return;

  if (inputDebounceTimer) clearTimeout(inputDebounceTimer);

  inputDebounceTimer = setTimeout(async () => {
    const text = getElementText(target);
    if (text.length < 8) return; // Too short to contain PII

    const result = await scanContent(text, "type");

    if (result.detections.length > 0 && result.action !== "LOG") {
      showUserNotification(
        result.userMessage || `${result.detections.length} sensitive item(s) detected while typing`,
        result.action === "BLOCK" ? "error" : "warning"
      );
    }
  }, INPUT_DEBOUNCE_MS);
}, true);

// ============================================================
// FILE UPLOAD INTERCEPTION
// Monitors file drop/upload on AI tool pages
// ============================================================

document.addEventListener("drop", async (event: DragEvent) => {
  if (!isEnabled) return;

  const files = event.dataTransfer?.files;
  if (!files || files.length === 0) return;

  for (const file of Array.from(files)) {
    // Only scan text-based files
    if (!isTextFile(file)) continue;

    const text = await readFileAsText(file);
    if (!text) continue;

    const result = await scanContent(text, "upload");

    if (result.action === "BLOCK") {
      event.preventDefault();
      event.stopImmediatePropagation();
      showUserNotification(
        `File "${file.name}" blocked: contains ${result.detections.map(d => d.entityType).join(", ")}`,
        "error"
      );
      return;
    }

    if (result.detections.length > 0) {
      showUserNotification(
        `File "${file.name}": ${result.detections.length} sensitive item(s) detected`,
        result.action === "WARN" ? "warning" : "info"
      );
    }
  }
}, true);

// Also monitor file input elements
document.addEventListener("change", async (event: Event) => {
  const target = event.target as HTMLInputElement;
  if (target.type !== "file" || !target.files) return;

  for (const file of Array.from(target.files)) {
    if (!isTextFile(file)) continue;
    const text = await readFileAsText(file);
    if (!text) continue;

    const result = await scanContent(text, "upload");
    if (result.detections.length > 0) {
      showUserNotification(
        `File "${file.name}": ${result.detections.length} sensitive item(s) detected`,
        result.action === "BLOCK" ? "error" : "warning"
      );
    }
  }
}, true);

// ============================================================
// FORM SUBMISSION INTERCEPTION
// Last line of defense before data is sent
// ============================================================

document.addEventListener("submit", async (event: SubmitEvent) => {
  if (!isEnabled) return;
  // Most AI tools use JS-driven submission, not form submit
  // This catches edge cases
}, true);

// Also watch for Enter key in prompt inputs (most AI tools submit on Enter)
document.addEventListener("keydown", async (event: KeyboardEvent) => {
  if (!isEnabled) return;
  if (event.key !== "Enter" || event.shiftKey) return; // Shift+Enter is newline

  const target = event.target as HTMLElement;
  if (!isPromptInput(target)) return;

  const text = getElementText(target);
  if (text.length < 5) return;

  const result = await scanContent(text, "prompt");

  if (result.action === "BLOCK") {
    event.preventDefault();
    event.stopImmediatePropagation();
    showUserNotification(result.userMessage || "Submission blocked: sensitive data detected", "error");
  }
}, true);

// ============================================================
// SCAN ORCHESTRATION
// ============================================================

async function scanContent(
  text: string,
  contentType: "paste" | "type" | "upload" | "prompt"
): Promise<{
  action: PolicyAction;
  detections: Partial<Detection>[];
  userMessage?: string;
  redactedContent?: string;
}> {
  // Step 1: Fast local regex scan
  const localResult = scanText(text);

  // Step 2: If nothing found locally, skip proxy call
  if (localResult.detections.length === 0) {
    return { action: "LOG", detections: [] };
  }

  // Step 3: Send to background script for proxy scan (if available)
  try {
    const proxyResult = await chrome.runtime.sendMessage({
      type: "SCAN_CONTENT",
      content: text,
      targetDomain: window.location.hostname,
      targetUrl: window.location.href,
      contentType,
    });

    if (proxyResult) {
      lastScanResult = proxyResult;
      return proxyResult;
    }
  } catch (err) {
    console.warn("[Sentinel] Background scan failed, using local results:", err);
  }

  // Fallback to local-only result
  const action = learningMode ? "LOG" : localResult.recommendedAction;

  return {
    action,
    detections: localResult.detections.map(d => ({
      entityType: d.entityType,
      confidence: d.confidence,
      contextRiskScore: d.contextRiskScore,
      redactedText: d.redactedText,
      startOffset: d.startOffset,
      endOffset: d.endOffset,
    })),
    userMessage: `${localResult.detections.length} sensitive item(s) detected: ${localResult.detections.map(d => d.entityType).join(", ")}`,
    redactedContent: localResult.recommendedAction === "REDACT"
      ? redactText(text, localResult.detections)
      : undefined,
  };
}

// ============================================================
// UI NOTIFICATIONS
// Shows non-intrusive banners to the user
// ============================================================

let activeNotification: HTMLElement | null = null;

function showUserNotification(message: string, level: "info" | "warning" | "error") {
  // Remove existing notification
  if (activeNotification) {
    activeNotification.remove();
  }

  const banner = document.createElement("div");
  banner.id = "sentinel-notification";
  banner.setAttribute("style", `
    position: fixed;
    top: 12px;
    right: 12px;
    z-index: 2147483647;
    max-width: 420px;
    padding: 12px 16px;
    border-radius: 8px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 13px;
    line-height: 1.4;
    color: #fff;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    animation: sentinelSlideIn 0.3s ease;
    cursor: pointer;
    background: ${
      level === "error" ? "#DC2626"
      : level === "warning" ? "#D97706"
      : "#2563EB"
    };
  `);

  banner.innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:8px;">
      <span style="font-size:16px;">${
        level === "error" ? "🛡️" : level === "warning" ? "⚠️" : "ℹ️"
      }</span>
      <div>
        <strong style="display:block;margin-bottom:2px;">Shadow AI Sentinel</strong>
        <span>${escapeHtml(message)}</span>
      </div>
      <span style="margin-left:auto;cursor:pointer;font-size:16px;opacity:0.7;" id="sentinel-close">×</span>
    </div>
  `;

  // Add slide-in animation
  const style = document.createElement("style");
  style.textContent = `
    @keyframes sentinelSlideIn {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
  `;
  banner.prepend(style);

  document.body.appendChild(banner);
  activeNotification = banner;

  // Close on click
  banner.addEventListener("click", () => banner.remove());

  // Auto-dismiss after 8 seconds (longer for errors)
  setTimeout(() => banner.remove(), level === "error" ? 12000 : 8000);
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

function isPromptInput(el: HTMLElement): boolean {
  // Detect the main prompt input on AI tool pages
  if (el instanceof HTMLTextAreaElement) return true;
  if (el instanceof HTMLInputElement && el.type === "text") return true;
  if (el.contentEditable === "true") {
    // Check if it looks like a prompt input (not a random editable div)
    const role = el.getAttribute("role");
    if (role === "textbox") return true;
    // Check parent containers for known AI tool prompt classes
    const classes = (el.className + " " + (el.parentElement?.className || "")).toLowerCase();
    if (classes.includes("prompt") || classes.includes("chat") || classes.includes("input") || classes.includes("compose")) {
      return true;
    }
  }
  return false;
}

function getElementText(el: HTMLElement): string {
  if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
    return el.value;
  }
  return el.textContent || el.innerText || "";
}

function isTextFile(file: File): boolean {
  const textTypes = [
    "text/", "application/json", "application/xml", "application/javascript",
    "application/typescript", "application/x-python", "application/sql",
    "application/yaml", "application/x-yaml", "application/csv",
  ];
  const textExtensions = [
    ".txt", ".md", ".csv", ".json", ".xml", ".yaml", ".yml",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java",
    ".c", ".cpp", ".h", ".sql", ".sh", ".env", ".conf", ".ini",
    ".log", ".html", ".css", ".scss",
  ];
  if (textTypes.some(t => file.type.startsWith(t))) return true;
  if (textExtensions.some(ext => file.name.toLowerCase().endsWith(ext))) return true;
  return false;
}

function readFileAsText(file: File): Promise<string | null> {
  return new Promise((resolve) => {
    if (file.size > 5 * 1024 * 1024) { // Skip files > 5MB
      resolve(null);
      return;
    }
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => resolve(null);
    reader.readAsText(file);
  });
}

function escapeHtml(text: string): string {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

// ============================================================
// INITIALIZATION
// ============================================================

console.log("[Shadow AI Sentinel] Content script loaded on", window.location.hostname);
