package main

// ============================================================
// main_test.go — Integration tests for the proxy HTTP API
//
// Tests run against real handler functions using httptest,
// no external services required (ML_SERVICE_URL="" → skipped).
//
// Coverage:
//   - POST /api/v1/scan: SSN block, email warn, token redact,
//     clean pass-through, learning mode, empty content
//   - GET  /api/v1/health: response shape
//   - GET  /api/v1/config: learning_mode env propagation
//   - POST /api/v1/events/batch: parse and accept
// ============================================================

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ============================================================
// HELPERS
// ============================================================

// testConfig returns a minimal Config suitable for unit tests.
func testConfig(learningMode bool) Config {
	return Config{
		LearningMode: learningMode,
		MLServiceURL: "", // no ML service in tests
		APIKey:       "", // no auth required in tests
		DefaultOrgID: "test-org",
	}
}

// postJSON sends a POST with a JSON body to the given handler.
func postJSON(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// decodeBody decodes the JSON response body into a map.
func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("failed to decode JSON response: %v\nbody: %s", err, w.Body.String())
	}
	return out
}

// scanAction extracts the "action" field from a scan response.
func scanAction(t *testing.T, body map[string]interface{}) string {
	t.Helper()
	a, ok := body["action"].(string)
	if !ok {
		t.Fatalf("missing or non-string 'action' field in response: %v", body)
	}
	return a
}

// ============================================================
// POST /api/v1/scan — ENFORCEMENT MODE (learningMode=false)
// ============================================================

func TestHandleScan_SSN_Block(t *testing.T) {
	handler := handleScan(testConfig(false))
	w := postJSON(t, handler, `{
		"content":      "My SSN is 078-05-1120",
		"targetDomain": "chatgpt.com",
		"contentType":  "paste"
	}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeBody(t, w)
	if scanAction(t, body) != "BLOCK" {
		t.Errorf("expected BLOCK for SSN, got %q", scanAction(t, body))
	}
	// CombinedRisk should be CRITICAL
	if body["combinedRisk"] != "CRITICAL" {
		t.Errorf("expected CRITICAL risk, got %v", body["combinedRisk"])
	}
	// detections should be an array
	detections, ok := body["detections"].([]interface{})
	if !ok || len(detections) == 0 {
		t.Errorf("expected non-empty detections array, got %v", body["detections"])
	}
	// userMessage should mention BLOCK
	msg, _ := body["userMessage"].(string)
	if !strings.Contains(strings.ToUpper(msg), "BLOCK") {
		t.Errorf("expected userMessage to mention BLOCK, got %q", msg)
	}
}

func TestHandleScan_CreditCard_Block(t *testing.T) {
	handler := handleScan(testConfig(false))
	// 4532015112830366 is a valid Visa number (passes Luhn)
	w := postJSON(t, handler, `{
		"content":      "Please charge card 4532015112830366",
		"targetDomain": "gemini.google.com"
	}`)

	body := decodeBody(t, w)
	if scanAction(t, body) != "BLOCK" {
		t.Errorf("expected BLOCK for credit card, got %q", scanAction(t, body))
	}
}

func TestHandleScan_Email_Warn(t *testing.T) {
	handler := handleScan(testConfig(false))
	w := postJSON(t, handler, `{
		"content":      "Please contact alice@example.com for more info",
		"targetDomain": "chatgpt.com"
	}`)

	body := decodeBody(t, w)
	action := scanAction(t, body)
	if action != "WARN" {
		t.Errorf("expected WARN for email, got %q (risk=%v)", action, body["combinedRisk"])
	}
}

func TestHandleScan_GitHubToken_Redact(t *testing.T) {
	handler := handleScan(testConfig(false))
	// High-entropy GitHub token → HIGH risk → REDACT
	w := postJSON(t, handler, `{
		"content":      "token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abc",
		"targetDomain": "claude.ai"
	}`)

	body := decodeBody(t, w)
	action := scanAction(t, body)
	if action != "REDACT" {
		t.Errorf("expected REDACT for GitHub token, got %q", action)
	}
	// redactedContent must be present and not contain the original token
	redacted, hasRedacted := body["redactedContent"].(string)
	if !hasRedacted || redacted == "" {
		t.Errorf("expected non-empty redactedContent in REDACT response, got %v", body["redactedContent"])
	}
	if strings.Contains(redacted, "ghp_") {
		t.Errorf("original token prefix still present in redactedContent: %q", redacted)
	}
}

func TestHandleScan_AWSKey_Block(t *testing.T) {
	handler := handleScan(testConfig(false))
	w := postJSON(t, handler, `{
		"content":      "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"targetDomain": "chatgpt.com"
	}`)

	body := decodeBody(t, w)
	action := scanAction(t, body)
	if action != "BLOCK" {
		t.Errorf("expected BLOCK for AWS key, got %q", action)
	}
}

func TestHandleScan_ConnectionString_Block(t *testing.T) {
	handler := handleScan(testConfig(false))
	w := postJSON(t, handler, `{
		"content":      "DATABASE_URL=postgres://user:pass@db.example.com:5432/prod",
		"targetDomain": "chatgpt.com"
	}`)

	body := decodeBody(t, w)
	action := scanAction(t, body)
	if action != "BLOCK" {
		t.Errorf("expected BLOCK for DB connection string, got %q", action)
	}
}

func TestHandleScan_CleanText_Log(t *testing.T) {
	handler := handleScan(testConfig(false))
	w := postJSON(t, handler, `{
		"content":      "Can you explain how transformers work in machine learning?",
		"targetDomain": "chatgpt.com"
	}`)

	body := decodeBody(t, w)
	action := scanAction(t, body)
	if action != "LOG" {
		t.Errorf("expected LOG for clean text, got %q", action)
	}
	// detections should be empty array, not null
	detections, ok := body["detections"].([]interface{})
	if !ok {
		t.Errorf("expected detections to be an array (not null), got %T: %v", body["detections"], body["detections"])
	} else if len(detections) != 0 {
		t.Errorf("expected 0 detections for clean text, got %d", len(detections))
	}
	// No userMessage for clean text
	msg, _ := body["userMessage"].(string)
	if msg != "" {
		t.Errorf("expected empty userMessage for clean text, got %q", msg)
	}
}

func TestHandleScan_EmptyContent_Log(t *testing.T) {
	handler := handleScan(testConfig(false))
	w := postJSON(t, handler, `{
		"content":      "",
		"targetDomain": "chatgpt.com"
	}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeBody(t, w)
	if scanAction(t, body) != "LOG" {
		t.Errorf("expected LOG for empty content, got %q", scanAction(t, body))
	}
}

func TestHandleScan_WhitespaceContent_Log(t *testing.T) {
	handler := handleScan(testConfig(false))
	w := postJSON(t, handler, `{"content": "   \n\t  "}`)

	body := decodeBody(t, w)
	if scanAction(t, body) != "LOG" {
		t.Errorf("expected LOG for whitespace content, got %q", scanAction(t, body))
	}
}

func TestHandleScan_InvalidJSON_Returns400(t *testing.T) {
	handler := handleScan(testConfig(false))
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{not valid json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

// ============================================================
// POST /api/v1/scan — LEARNING MODE (learningMode=true)
// ============================================================

func TestHandleScan_LearningMode_SSN_ReturnsLog(t *testing.T) {
	// In learning mode, even CRITICAL PII returns LOG (detect but don't block)
	handler := handleScan(testConfig(true))
	w := postJSON(t, handler, `{
		"content":      "SSN: 078-05-1120",
		"targetDomain": "chatgpt.com"
	}`)

	body := decodeBody(t, w)
	action := scanAction(t, body)
	if action != "LOG" {
		t.Errorf("expected LOG in learning mode for SSN, got %q", action)
	}
	// Detections are still reported (we saw it, but didn't act)
	detections, _ := body["detections"].([]interface{})
	if len(detections) == 0 {
		t.Error("expected detections to be reported even in learning mode")
	}
	// User message should mention Learning Mode
	msg, _ := body["userMessage"].(string)
	if !strings.Contains(msg, "Learning Mode") {
		t.Errorf("expected learning mode indicator in userMessage, got %q", msg)
	}
}

func TestHandleScan_LearningMode_Token_NoRedactedContent(t *testing.T) {
	// In learning mode, action is LOG so redactedContent should not be present
	handler := handleScan(testConfig(true))
	w := postJSON(t, handler, `{
		"content": "token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abc"
	}`)

	body := decodeBody(t, w)
	if body["redactedContent"] != nil {
		t.Errorf("expected no redactedContent in learning mode, got: %v", body["redactedContent"])
	}
}

// ============================================================
// GET /api/v1/health
// ============================================================

func TestHandleHealth_Returns200(t *testing.T) {
	handler := handleHealth(testConfig(false))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeBody(t, w)
	if body["status"] != "healthy" {
		t.Errorf("expected status=healthy, got %v", body["status"])
	}
}

func TestHandleHealth_ReflectsLearningMode(t *testing.T) {
	handler := handleHealth(testConfig(true))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body := decodeBody(t, w)
	lm, _ := body["learning_mode"].(bool)
	if !lm {
		t.Errorf("expected learning_mode=true in health response, got %v", body["learning_mode"])
	}
}

// ============================================================
// GET /api/v1/config
// ============================================================

func TestHandleGetConfig_LearningModeFalse(t *testing.T) {
	handler := handleGetConfig(testConfig(false))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := decodeBody(t, w)
	lm, _ := body["learningMode"].(bool)
	if lm {
		t.Errorf("expected learningMode=false, got %v", body["learningMode"])
	}
}

func TestHandleGetConfig_LearningModeTrue(t *testing.T) {
	handler := handleGetConfig(testConfig(true))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body := decodeBody(t, w)
	lm, _ := body["learningMode"].(bool)
	if !lm {
		t.Errorf("expected learningMode=true, got %v", body["learningMode"])
	}
}

func TestHandleGetConfig_HasEnabledDetectors(t *testing.T) {
	handler := handleGetConfig(testConfig(false))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	body := decodeBody(t, w)
	detectors, ok := body["enabledDetectors"].([]interface{})
	if !ok || len(detectors) == 0 {
		t.Errorf("expected non-empty enabledDetectors, got %v", body["enabledDetectors"])
	}
}

// ============================================================
// POST /api/v1/events/batch
// ============================================================

func TestHandleEventBatch_AcceptsValidBatch(t *testing.T) {
	handler := handleEventBatch()
	w := postJSON(t, handler, `{
		"auditEvents":    [{"id": "1", "eventType": "scan"}],
		"shadowAiEvents": [{"id": "2", "domain": "chatgpt.com"}]
	}`)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202 Accepted, got %d", w.Code)
	}
}

func TestHandleEventBatch_EmptyBatch_Accepts(t *testing.T) {
	handler := handleEventBatch()
	w := postJSON(t, handler, `{"auditEvents": [], "shadowAiEvents": []}`)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202 Accepted for empty batch, got %d", w.Code)
	}
}

func TestHandleEventBatch_InvalidJSON_Returns400(t *testing.T) {
	handler := handleEventBatch()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

// ============================================================
// HELPER FUNCTIONS (tested implicitly via handlers above)
// ============================================================

func TestBuildUserMessage_Block(t *testing.T) {
	msg := buildUserMessage("BLOCK", []string{"SSN", "CREDIT_CARD"}, false)
	if !strings.Contains(msg, "Blocked") {
		t.Errorf("expected 'Blocked' in BLOCK message, got %q", msg)
	}
	if !strings.Contains(msg, "SSN") {
		t.Errorf("expected entity type in message, got %q", msg)
	}
}

func TestBuildUserMessage_LearningMode(t *testing.T) {
	msg := buildUserMessage("LOG", []string{"EMAIL"}, true)
	if !strings.Contains(msg, "Learning Mode") {
		t.Errorf("expected 'Learning Mode' in learning mode message, got %q", msg)
	}
}

func TestBuildUserMessage_NoDetections_Empty(t *testing.T) {
	msg := buildUserMessage("LOG", nil, false)
	if msg != "" {
		t.Errorf("expected empty message for no detections, got %q", msg)
	}
}

