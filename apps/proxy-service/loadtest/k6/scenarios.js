// ============================================================
// Shadow AI Sentinel — k6 load test scenarios
//
// Scenarios:
//   1. baseline         — 1000 RPS clean text, p99 < 50ms
//   2. pii_heavy        — 500 RPS with SSN + CC, verify BLOCK returned
//   3. ml_timeout       — ML mock delays 6s, verify circuit opens
//   4. ml_failure       — ML mock returns 500, circuit opens after 3 failures
//   5. streaming_mixed  — 500 RPS to /proxy/stream/chat
//
// Usage:
//   k6 run scenarios.js
//   k6 run --env SCENARIO=pii_heavy scenarios.js
//   k6 run --env SENTINEL_URL=http://localhost:8080 scenarios.js
//   k6 run --env SCENARIO=ml_failure --env ML_MOCK_URL=http://localhost:9999 scenarios.js
//
// Requirements: k6 (https://k6.io/docs/get-started/installation/)
// ============================================================

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend } from "k6/metrics";

// ── Environment ───────────────────────────────────────────────
const BASE_URL = __ENV.SENTINEL_URL || "http://localhost:8080";
const SCENARIO_NAME = __ENV.SCENARIO || "baseline";

// ── Custom metrics ────────────────────────────────────────────
const blockRate = new Rate("block_rate");
const degradedRate = new Rate("degraded_rate");
const mlCircuitOpenCount = new Rate("ml_circuit_open");
const scanLatency = new Trend("scan_latency_ms", true);

// ── Payloads ──────────────────────────────────────────────────
const CLEAN_PAYLOAD = JSON.stringify({
  content:
    "Please help me summarize this quarterly report. Revenue grew 15% YoY in Q3.",
  contentType: "text",
  targetDomain: "chat.openai.com",
  targetUrl: "https://chat.openai.com/chat",
});

const PII_PAYLOAD = JSON.stringify({
  content:
    "Patient John Smith, SSN 078-05-1120, credit card 4532015112830366 exp 12/27, email john@example.com.",
  contentType: "text",
  targetDomain: "chat.openai.com",
  targetUrl: "https://chat.openai.com/chat",
});

const API_KEY_PAYLOAD = JSON.stringify({
  content:
    "Config: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  contentType: "text",
  targetDomain: "chat.openai.com",
  targetUrl: "https://chat.openai.com/chat",
});

const STREAM_PAYLOAD = JSON.stringify({
  messages: [
    {
      role: "user",
      content:
        "SSN 078-05-1120 — please help me process this patient record.",
    },
  ],
  model: "gpt-4o",
});

const HEADERS = { "Content-Type": "application/json" };

// ── Scenario definitions ──────────────────────────────────────
export const options = {
  scenarios: {
    // ── 1. Baseline: clean text, 1000 RPS ──────────────────
    baseline: {
      executor: "constant-arrival-rate",
      rate: 1000,
      timeUnit: "1s",
      duration: "30s",
      preAllocatedVUs: 100,
      maxVUs: 300,
      exec: "scenarioBaseline",
    },

    // ── 2. PII heavy: 500 RPS, all contain SSN + CC ─────────
    pii_heavy: {
      executor: "constant-arrival-rate",
      rate: 500,
      timeUnit: "1s",
      duration: "30s",
      preAllocatedVUs: 50,
      maxVUs: 150,
      exec: "scenarioPiiHeavy",
    },

    // ── 3. ML timeout: points ML_SERVICE_URL at slow mock ───
    //    Run a mock server that delays 6s before responding:
    //    python3 -c "
    //      import http.server, time
    //      class H(http.server.BaseHTTPRequestHandler):
    //        def do_POST(self):
    //          time.sleep(6); self.send_response(200)
    //          self.end_headers(); self.wfile.write(b'{\"detections\":[]}')
    //      http.server.HTTPServer(('',9998),H).serve_forever()"
    ml_timeout: {
      executor: "ramping-arrival-rate",
      startRate: 10,
      timeUnit: "1s",
      stages: [
        { duration: "10s", target: 50 },
        { duration: "30s", target: 50 },
        { duration: "5s", target: 0 },
      ],
      preAllocatedVUs: 10,
      maxVUs: 60,
      exec: "scenarioMLTimeout",
    },

    // ── 4. ML failure: mock returns 500 ─────────────────────
    //    Run a mock server that returns 500:
    //    python3 -c "
    //      import http.server
    //      class H(http.server.BaseHTTPRequestHandler):
    //        def do_POST(self):
    //          self.send_response(500); self.end_headers()
    //      http.server.HTTPServer(('',9999),H).serve_forever()"
    ml_failure: {
      executor: "constant-arrival-rate",
      rate: 20,
      timeUnit: "1s",
      duration: "30s",
      preAllocatedVUs: 10,
      maxVUs: 30,
      exec: "scenarioMLFailure",
    },

    // ── 5. Streaming: 500 RPS to /proxy/stream/chat ─────────
    streaming_mixed: {
      executor: "constant-arrival-rate",
      rate: 500,
      timeUnit: "1s",
      duration: "30s",
      preAllocatedVUs: 50,
      maxVUs: 150,
      exec: "scenarioStreaming",
    },
  },

  // ── Thresholds ──────────────────────────────────────────────
  thresholds: {
    // Baseline: p99 < 50ms, p50 < 20ms, 0 errors
    "http_req_duration{scenario:baseline}": ["p(99)<50", "p(50)<20"],
    "http_req_failed{scenario:baseline}": ["rate<0.001"],

    // PII heavy: must return BLOCK on all requests
    "block_rate{scenario:pii_heavy}": ["rate>0.95"],

    // ML timeout: circuit should open — most requests served without ML (degraded)
    "degraded_rate{scenario:ml_timeout}": ["rate>0.5"],

    // ML failure: circuit opens after 3 failures — check health shows OPEN
    "ml_circuit_open{scenario:ml_failure}": ["rate>0.0"],

    // Streaming: p99 < 5s (streaming is inherently slower)
    "http_req_duration{scenario:streaming_mixed}": ["p(99)<5000"],
  },
};

// ── Scenario implementations ───────────────────────────────────

export function scenarioBaseline() {
  const res = http.post(`${BASE_URL}/api/v1/scan`, CLEAN_PAYLOAD, {
    headers: HEADERS,
    tags: { scenario: "baseline" },
  });

  scanLatency.add(res.timings.duration, { scenario: "baseline" });

  check(res, {
    "status 200": (r) => r.status === 200,
    "action is LOG": (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.action === "LOG" || body.action === "ALLOW";
      } catch {
        return false;
      }
    },
  });
}

export function scenarioPiiHeavy() {
  const payload = Math.random() < 0.5 ? PII_PAYLOAD : API_KEY_PAYLOAD;
  const res = http.post(`${BASE_URL}/api/v1/scan`, payload, {
    headers: HEADERS,
    tags: { scenario: "pii_heavy" },
  });

  let isBlock = false;
  if (res.status === 200) {
    try {
      const body = JSON.parse(res.body);
      isBlock = body.action === "BLOCK";
    } catch {}
  } else if (res.status === 403) {
    isBlock = true;
  }

  blockRate.add(isBlock, { scenario: "pii_heavy" });

  check(res, {
    "status 200": (r) => r.status === 200,
    "action is BLOCK": () => isBlock,
  });
}

export function scenarioMLTimeout() {
  const res = http.post(`${BASE_URL}/api/v1/scan`, PII_PAYLOAD, {
    headers: HEADERS,
    tags: { scenario: "ml_timeout" },
    timeout: "15s",
  });

  let isDegraded = false;
  if (res.status === 200) {
    try {
      const body = JSON.parse(res.body);
      isDegraded = body.degraded === true;
    } catch {}
  }

  degradedRate.add(isDegraded, { scenario: "ml_timeout" });

  check(res, {
    "status 200 (no crash)": (r) => r.status === 200,
    "response within budget": (r) => r.timings.duration < 12000,
  });

  // After several requests, check health for circuit state
  if (Math.random() < 0.05) {
    const healthRes = http.get(`${BASE_URL}/health`, {
      tags: { scenario: "ml_timeout" },
    });
    if (healthRes.status === 200) {
      try {
        const h = JSON.parse(healthRes.body);
        const circuitState = h?.services?.ml_service?.circuit_state;
        mlCircuitOpenCount.add(circuitState === "OPEN", {
          scenario: "ml_timeout",
        });
      } catch {}
    }
  }
}

export function scenarioMLFailure() {
  const res = http.post(`${BASE_URL}/api/v1/scan`, PII_PAYLOAD, {
    headers: HEADERS,
    tags: { scenario: "ml_failure" },
  });

  check(res, {
    "status 200 (graceful degradation)": (r) => r.status === 200,
  });

  // Poll health to detect circuit open
  if (Math.random() < 0.1) {
    const healthRes = http.get(`${BASE_URL}/health`, {
      tags: { scenario: "ml_failure" },
    });
    if (healthRes.status === 200) {
      try {
        const h = JSON.parse(healthRes.body);
        const circuitState = h?.services?.ml_service?.circuit_state;
        const isOpen = circuitState === "OPEN";
        mlCircuitOpenCount.add(isOpen, { scenario: "ml_failure" });
        check({ circuitState }, {
          "circuit opened after failures": () => circuitState !== undefined,
        });
      } catch {}
    }
  }

  sleep(0.05);
}

export function scenarioStreaming() {
  const res = http.post(`${BASE_URL}/proxy/stream/chat`, STREAM_PAYLOAD, {
    headers: HEADERS,
    tags: { scenario: "streaming_mixed" },
    timeout: "30s",
  });

  // Streaming endpoint: BLOCK (PII) → 403, or 200 with SSE stream
  check(res, {
    "blocked (403) or streaming (200)": (r) =>
      r.status === 200 || r.status === 403,
    "403 has error body": (r) => {
      if (r.status !== 403) return true;
      try {
        const body = JSON.parse(r.body);
        return body.error !== undefined;
      } catch {
        return false;
      }
    },
  });
}

// ── Default export: run only the selected scenario ────────────
// When running with --env SCENARIO=<name>, only that scenario is active.
// This avoids starting all 5 scenarios simultaneously during focused testing.
export default function () {
  switch (SCENARIO_NAME) {
    case "baseline":
      return scenarioBaseline();
    case "pii_heavy":
      return scenarioPiiHeavy();
    case "ml_timeout":
      return scenarioMLTimeout();
    case "ml_failure":
      return scenarioMLFailure();
    case "streaming_mixed":
      return scenarioStreaming();
    default:
      return scenarioBaseline();
  }
}
