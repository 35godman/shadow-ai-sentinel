# Shadow AI Sentinel — Fix Plan: Make PII Detection & Blocking Actually Work

## Group Decision Record

**Participants:** PM, Senior Backend Engineer (Go), Senior Frontend Engineer (Extension), Senior Architect

**Problem Statement:** The product detects PII but never blocks, redacts, or modifies anything. All detections result in `LOG` due to 5 compounding bugs across 3 layers. The scanner, redactor, policy engine, and LLM router are fully implemented but are dead code — never imported or called.

**Goal:** Wire everything together so the full pipeline works: Scan → Policy Evaluate → Block/Redact/Warn/Log → (if Redact) send sanitized content → re-identify response.

---

## Bug Inventory (What's Broken)

| # | Layer | File | Bug | Severity |
|---|---|---|---|---|
| B1 | Proxy | `main.go:154-166` | Scanner package never imported; uses empty `detections` slice and hardcoded `action = "LOG"` | CRITICAL |
| B2 | Proxy | `main.go:166` | Action is hardcoded to `"LOG"` — never uses policy engine or scanner's `determineAction()` | CRITICAL |
| B3 | Proxy | `main.go:213-279` | `/proxy/chat` forwards messages to LLMs with zero scanning — no redaction, no policy check | CRITICAL |
| B4 | Proxy | `main.go:86-87` | Auth middleware commented out (`// r.Use(middleware.APIKeyAuth(...))`). Anyone can call the API | HIGH |
| B5 | Proxy | `main.go:168-178` | Response doesn't include `redactedContent` field — extension can't redact even if it wanted to | HIGH |
| B6 | Proxy | `main.go:288-291` | Event batch handler is a no-op (`w.WriteHeader(http.StatusAccepted)`) — events are discarded | MEDIUM |
| B7 | Proxy | `main.go:298-307` | Config endpoint hardcodes `learningMode: true` — overrides any user toggle on every poll | HIGH |
| B8 | Extension | `background/index.ts:17` | `learningMode: true` by default. Combined with B7, it can never be turned off persistently | HIGH |
| B9 | Extension | `background/index.ts:205` | `if (!config.apiKey) return null` — apiKey defaults to `""`, so proxy is never called | HIGH |
| B10 | Extension | `content/index.ts:228` | Fallback also checks `learningMode` and downgrades to `LOG` | MEDIUM |
| B11 | Extension | `background/index.ts:181-192` | Response to content script never includes `redactedContent` — REDACT action has no effect | HIGH |
| B12 | Proxy | Dead code | `scanner/scanner.go`, `redactor/redactor.go`, `policy/engine.go`, `router/llm_router.go` — all fully implemented, none imported | CRITICAL |
| B13 | Proxy | Dead code | `middleware/auth.go` (163 lines) — APIKeyAuth + JWTAuth fully implemented, never wired in `main.go` | HIGH |
| B14 | Proxy | Dead code | `db/store.go` (423 lines) — PostgreSQL + Redis store fully implemented, never instantiated in `main.go` | MEDIUM |
| B15 | Proxy | No test files | Zero Go test files exist (`*_test.go` — none found) | MEDIUM |

---

## Implementation Plan

### Phase A: Wire the Proxy Scan Pipeline (Fixes B1, B2, B5, B12)

**Owner:** Senior Backend Engineer
**Files:** `apps/proxy-service/src/main.go`
**Depends on:** Nothing

**What to do:**

1. **Import the scanner package** in `main.go`:
   ```go
   import "github.com/shadow-ai-sentinel/proxy-service/src/scanner"
   ```

2. **Replace the stub scan logic** (lines 154-178) with real scanner call:
   ```go
   // Step 1: Server-side regex scan
   scanResult := scanner.ScanText(req.Content, nil) // nil = all patterns enabled

   // Step 2: Call ML service (additive)
   mlDetections := callMLService(cfg.MLServiceURL, req.Content)
   // Merge ML detections into scanResult if any

   // Step 3: Determine action from scan result (not hardcoded)
   action := scanResult.RecommendedAction
   ```

3. **Import and use the redactor** when action is `REDACT`:
   ```go
   import "github.com/shadow-ai-sentinel/proxy-service/src/redactor"
   ```
   When action is `REDACT`, call `redactor.Redact()` and include `redactedContent` in the JSON response.

4. **Return the proper response shape** that the extension expects:
   ```json
   {
     "action": "REDACT",
     "detections": [...],
     "combinedRisk": "HIGH",
     "userMessage": "HIGH: EMAIL, PHONE detected.",
     "redactedContent": "My email is [EMAIL_1] and phone is [PHONE_1]"
   }
   ```

**Acceptance criteria:**
- `POST /api/v1/scan` with text containing an SSN returns `action: "BLOCK"`
- `POST /api/v1/scan` with text containing an email returns `action: "WARN"`
- `POST /api/v1/scan` with text containing a GitHub token returns `action: "REDACT"` with `redactedContent` populated
- `POST /api/v1/scan` with clean text returns `action: "LOG"` with empty detections

---

### Phase B: Wire the Proxy Chat Pipeline with Scan + Redact (Fixes B3)

**Owner:** Senior Backend Engineer
**Files:** `apps/proxy-service/src/main.go`
**Depends on:** Phase A

**What to do:**

1. **Import and initialize the LLM router** (`router/llm_router.go`) in `main.go`:
   ```go
   import "github.com/shadow-ai-sentinel/proxy-service/src/router"
   ```

2. **Scan all message content** in `handleProxyChat` before forwarding:
   - Concatenate all message contents
   - Run through `scanner.ScanText()`
   - Apply policy decision

3. **If action is BLOCK**: return error response immediately, don't forward

4. **If action is REDACT**:
   - Call `redactor.Redact()` on the message content
   - Store the redaction mappings
   - Forward redacted messages to LLM via `router.Forward()`
   - On response, call `redactor.ReIdentify()` to restore originals
   - Call `redactor.ScanResponseForHallucinatedPII()` as safety check

5. **If action is WARN or LOG**: forward as-is (but log the event)

6. **Replace inline provider switch** with `router.Decide()` + `router.Forward()`

**Acceptance criteria:**
- `POST /proxy/chat` with SSN in message → 403 blocked response
- `POST /proxy/chat` with email in message → email redacted before reaching LLM, restored in response
- `POST /proxy/chat` with clean message → forwarded normally

---

### Phase C: Fix the Config Endpoint (Fixes B7)

**Owner:** Senior Backend Engineer
**Files:** `apps/proxy-service/src/main.go`
**Depends on:** Nothing (can parallel with A)

**What to do:**

1. **Remove hardcoded `learningMode: true`** from `handleGetConfig` (line 301)

2. **Make config endpoint org-aware**: Read the org's config from the database (or at minimum, respect a `LEARNING_MODE` environment variable so operators can control it)

3. For now (without DB), use environment variable:
   ```go
   "learningMode": getEnv("LEARNING_MODE", "false") == "true",
   ```
   This makes the default `false` (enforcing mode) — the safe default for a DLP product.

**Acceptance criteria:**
- `GET /api/v1/config` returns `learningMode: false` by default
- Setting `LEARNING_MODE=true` env var returns `learningMode: true`
- Extension config polling picks up the change

---

### Phase D: Fix the Extension Side (Fixes B8, B9, B10, B11)

**Owner:** Senior Frontend Engineer
**Files:** `apps/browser-extension/src/background/index.ts`, `apps/browser-extension/src/content/index.ts`
**Depends on:** Phase A (proxy must return correct responses)

**What to do:**

1. **Change `learningMode` default to `false`** in `background/index.ts:17`:
   ```ts
   learningMode: false, // Enforce by default — learning mode is opt-in
   ```

2. **Remove the `apiKey` guard** in `sendToProxy` (line 205). The proxy should work without API key auth in development. Change to:
   ```ts
   if (!config.proxyEndpoint) return null;
   ```
   (Auth enforcement is the proxy's job via middleware, not the extension's job to self-censor)

3. **Include `redactedContent` in background response** to content script (`handleScanRequest`, around line 181-192):
   - Import `redactText` from `@sentinel/regex-patterns`
   - When action is `REDACT`, compute `redactedContent`:
     ```ts
     redactedContent: action === "REDACT"
       ? redactText(content, scanResult.detections)
       : undefined,
     ```
   - Also pass through `redactedContent` from proxy response if available

4. **Push config updates to content scripts** when config changes. After `saveConfig()`, broadcast:
   ```ts
   chrome.tabs.query({}, (tabs) => {
     tabs.forEach(tab => {
       if (tab.id) chrome.tabs.sendMessage(tab.id, { type: "CONFIG_UPDATE", config });
     });
   });
   ```

5. **Content script listens for config updates** (new listener in `content/index.ts`):
   ```ts
   chrome.runtime.onMessage.addListener((message) => {
     if (message.type === "CONFIG_UPDATE") {
       learningMode = message.config.learningMode ?? false;
     }
   });
   ```

**Acceptance criteria:**
- Extension calls proxy even without apiKey configured
- When proxy returns `REDACT`, the paste event inserts redacted text
- When proxy returns `BLOCK`, the paste event is prevented
- Toggling learning mode in popup persists and reaches content script

---

### Phase E: Wire Auth Middleware (Fixes B4, B13)

**Owner:** Senior Backend Engineer
**Files:** `apps/proxy-service/src/main.go`
**Depends on:** Nothing (can parallel)

**What to do:**

The `middleware/auth.go` file already has a complete `APIKeyAuth` middleware implementation (lines 34-70). It extracts API keys from `Authorization: Bearer` or `X-API-Key` headers and validates via a lookup function. **Do not rewrite it — wire it.**

1. **Import the existing middleware package** in `main.go`:
   ```go
   import mw "github.com/shadow-ai-sentinel/proxy-service/src/middleware"
   ```

2. **Wire `APIKeyAuth` into the `/api/v1` route group** with a dev-friendly lookup function. For Phase 1 (without DB), validate against an environment variable:
   ```go
   r.Route("/api/v1", func(r chi.Router) {
       apiKey := getEnv("API_KEY", "")
       if apiKey != "" {
           r.Use(mw.APIKeyAuth(func(ctx context.Context, key string) (string, error) {
               if key == apiKey {
                   return getEnv("DEFAULT_ORG_ID", "dev-org"), nil
               }
               return "", fmt.Errorf("invalid key")
           }))
       }
       // ... routes ...
   })
   ```

3. **Wire `JWTAuth` for the dashboard routes**:
   ```go
   r.Route("/api/v1/dashboard", func(r chi.Router) {
       r.Use(mw.JWTAuth(cfg.JWTSecret))
       // ... routes ...
   })
   ```

4. **Keep dev-friendly**: if `API_KEY` env is empty, skip the middleware entirely (no auth in development). Only enforce when explicitly configured.

**Acceptance criteria:**
- With no `API_KEY` env set: all requests pass through (dev mode)
- With `API_KEY=my-secret`: requests without valid `Authorization: Bearer my-secret` get 401
- Extension with matching apiKey can call the proxy
- Dashboard routes require valid JWT

---

### Phase F: Wire Event Batch Storage (Fixes B6)

**Owner:** Senior Backend Engineer
**Files:** `apps/proxy-service/src/main.go`
**Depends on:** Nothing (can parallel)

**What to do:**

1. For Phase 1 (no persistent DB wired), at minimum **log the events** instead of silently discarding:
   ```go
   func handleEventBatch() http.HandlerFunc {
       return func(w http.ResponseWriter, r *http.Request) {
           var batch struct {
               AuditEvents   []json.RawMessage `json:"auditEvents"`
               ShadowAiEvents []json.RawMessage `json:"shadowAiEvents"`
           }
           if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
               jsonError(w, "Invalid batch", http.StatusBadRequest)
               return
           }
           log.Printf("[Sentinel] Received event batch: %d audit, %d shadow-ai",
               len(batch.AuditEvents), len(batch.ShadowAiEvents))
           w.WriteHeader(http.StatusAccepted)
       }
   }
   ```

2. **Phase 2**: Wire to PostgreSQL via `pgx` (dependency already in `go.mod`).

**Acceptance criteria:**
- Event batches from the extension are logged to stdout
- Events are not silently discarded

---

### Phase G: Add Go Tests (Fixes B15)

**Owner:** Senior Backend Engineer
**Files:** New `*_test.go` files
**Depends on:** Phase A

**What to do:**

1. **`scanner/scanner_test.go`** — table-driven tests mirroring the TypeScript regex-patterns tests:
   - SSN detection + validation
   - Credit card + Luhn
   - API key + entropy
   - False positive prevention (dates, 9-digit numbers that aren't SSNs)
   - Combined risk scoring
   - Action determination

2. **`redactor/redactor_test.go`**:
   - Basic redaction with numbered placeholders
   - Consistent placeholders for repeated values
   - Re-identification round-trip
   - Hallucinated PII detection

3. **`policy/engine_test.go`**:
   - Rule matching with various conditions
   - Priority ordering
   - Default action fallback

4. **`main_test.go`** (integration):
   - HTTP tests for `/api/v1/scan` endpoint
   - HTTP tests for `/api/v1/health`

**Acceptance criteria:**
- `go test ./...` passes from `apps/proxy-service/`
- Coverage on scanner, redactor, and policy packages

---

## Execution Order & Dependencies

```
Can run in parallel:
├── Phase A: Wire Proxy Scan Pipeline ──→ Phase B: Wire Proxy Chat Pipeline
├── Phase C: Fix Config Endpoint        ──→ Phase D: Fix Extension (after A+C)
├── Phase E: Wire Auth Middleware
└── Phase F: Wire Event Batch Storage

Sequential:
Phase A ──→ Phase D: Fix Extension Side (needs proxy returning correct responses)
Phase C ──→ Phase D: Fix Extension Side (config must not override learningMode)
Phase A ──→ Phase G: Add Go Tests (needs scanner wired in)
Phase A ──→ Phase B: Wire Proxy Chat (needs scan pipeline working)
```

**Recommended order for a single developer:**
1. Phase A (scanner + redactor wiring — unblocks everything)
2. Phase C (config fix — quick win, prevents config from overriding learning mode toggle)
3. Phase D (extension fixes — makes blocking work end-to-end)
4. Phase B (proxy chat pipeline — adds redaction to LLM forwarding)
5. Phase E (auth middleware — wire existing `middleware/auth.go`)
6. Phase F (event storage — stop discarding events)
7. Phase G (tests — validate everything works)

**Not in scope (Phase 2):**
- Wire `db/store.go` (requires DB migrations, schema creation)
- Wire policy engine to DB-stored rules (requires `db/store.go`)
- ML service integration testing (requires ML service running)

---

## Dead Code Inventory (All Fully Implemented, None Used)

This is the complete list of implemented packages that `main.go` never imports or calls. None of this is stub code — it's all production-ready and waiting to be wired.

| Package | File | Lines | What It Does | When to Wire |
|---|---|---|---|---|
| `scanner` | `src/scanner/scanner.go` | 384 | 20+ regex patterns, validators (Luhn, SSN, entropy), risk scoring, `ScanText()` | **Phase A** |
| `redactor` | `src/redactor/redactor.go` | 122 | Numbered placeholder redaction, re-identification, hallucination detection | **Phase A + B** |
| `policy` | `src/policy/engine.go` | 244 | Rule evaluation with conditions (entity_type, ai_tool, sensitivity, confidence) | **Phase B** (optional, scanner has built-in `determineAction`) |
| `router` | `src/router/llm_router.go` | 340 | Smart routing (on-prem for sensitive, external for clean), OpenAI/Anthropic/Ollama | **Phase B** |
| `middleware` | `src/middleware/auth.go` | 163 | API key auth + JWT auth + context getters | **Phase E** |
| `db` | `src/db/store.go` | 423 | PostgreSQL + Redis: org config, policies, audit events, redaction session cache | **Phase 2** (requires DB schema + migrations) |

**Note on `db/store.go`:** This package requires PostgreSQL tables (`organizations`, `policy_rules`, `audit_events`, `shadow_ai_events`, `mv_user_risk_scores`, `mv_department_risk`) that don't exist yet. Wiring it requires creating a database migration first. This is out of scope for the current fix and belongs in Phase 2 when the full DB layer is set up. For now, the proxy operates without persistent storage — config comes from env vars, events are logged to stdout.

---

## End-to-End Verification Checklist

After all phases, verify:

- [ ] Paste an SSN (`078-05-1120`) into ChatGPT → paste is **blocked**, red banner shown
- [ ] Paste an email (`john@example.com`) into ChatGPT → **warning** banner shown
- [ ] Paste a GitHub token (`ghp_abc...`) into ChatGPT → paste is **redacted**, `[API_KEY_1]` inserted instead
- [ ] Paste clean text → no notification, text passes through
- [ ] Toggle learning mode ON in popup → detections show as "Learning Mode: ... No action taken"
- [ ] Toggle learning mode OFF in popup → detections enforce BLOCK/REDACT/WARN
- [ ] Proxy `/api/v1/scan` returns correct action and `redactedContent`
- [ ] Proxy `/proxy/chat` blocks messages with SSN/credit card
- [ ] Proxy `/proxy/chat` redacts emails/tokens before forwarding to LLM
- [ ] Proxy `/proxy/chat` re-identifies placeholders in LLM response
- [ ] Event batches from extension are logged by proxy
- [ ] Extension popup shows correct stats (scans, warnings, blocked counts)
- [ ] `go test ./...` passes
- [ ] `npm run test` passes (regex-patterns tests still green)
