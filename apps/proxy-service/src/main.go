package main

// ============================================================
// Shadow AI Sentinel — Proxy Service
// HTTP server: scan endpoint, LLM proxy, event logging, config.
//
// Package wiring:
//   scanner   → regex + validator-based PII detection
//   redactor  → numbered-placeholder redaction + re-identification
//   policy    → rule evaluation (Phase 2: rules loaded from DB)
//   router    → LLM routing (on-prem vs external, provider selection)
//   middleware → API key + JWT auth
//
// Logging: uses standard log for now.
// TODO(Phase 2): replace with go.uber.org/zap for structured logging.
// ============================================================

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	sentinelmw "github.com/shadow-ai-sentinel/proxy-service/src/middleware"
	"github.com/shadow-ai-sentinel/proxy-service/src/policy"
	"github.com/shadow-ai-sentinel/proxy-service/src/redactor"
	llmrouter "github.com/shadow-ai-sentinel/proxy-service/src/router"
	"github.com/shadow-ai-sentinel/proxy-service/src/scanner"
)

// ============================================================
// CONFIG
// ============================================================

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	Port         string
	DatabaseURL  string
	RedisURL     string
	MLServiceURL string
	OllamaURL    string
	JWTSecret    string
	OnPremMode   bool
	Environment  string
	OpenAIKey    string
	AnthropicKey string
	GoogleKey    string
	DefaultModel string

	// LearningMode: detect but never block/redact. Server-authoritative.
	// Set via LEARNING_MODE=true env var. Default: false (enforce).
	LearningMode bool

	// APIKey: if set, all /api/v1 and /proxy requests require
	// Authorization: Bearer <key>. Empty = open (dev mode).
	APIKey string

	// DefaultOrgID: org ID injected into context when no DB is available.
	DefaultOrgID string
}

func loadConfig() Config {
	return Config{
		Port:         getEnv("PORT", "8080"),
		DatabaseURL:  getEnv("DATABASE_URL", "postgres://sentinel:sentinel-dev-password@localhost:5432/sentinel?sslmode=disable"),
		RedisURL:     getEnv("REDIS_URL", "redis://:sentinel-dev-redis@localhost:6379"),
		MLServiceURL: getEnv("ML_SERVICE_URL", ""),
		OllamaURL:    getEnv("OLLAMA_URL", "http://localhost:11434"),
		JWTSecret:    getEnv("JWT_SECRET", "dev-secret-change-in-production"),
		OnPremMode:   getEnv("ONPREM_MODE", "false") == "true",
		Environment:  getEnv("ENVIRONMENT", "development"),
		OpenAIKey:    getEnv("OPENAI_API_KEY", ""),
		AnthropicKey: getEnv("ANTHROPIC_API_KEY", ""),
		GoogleKey:    getEnv("GOOGLE_AI_KEY", ""),
		DefaultModel: getEnv("DEFAULT_ONPREM_MODEL", "llama3.1"),
		LearningMode: getEnv("LEARNING_MODE", "false") == "true",
		APIKey:       getEnv("API_KEY", ""),
		DefaultOrgID: getEnv("DEFAULT_ORG_ID", "dev-org"),
	}
}

// ============================================================
// MAIN
// ============================================================

func main() {
	cfg := loadConfig()

	// Initialize LLM router once — reused across all /proxy/chat requests.
	llmRouter := llmrouter.NewRouter(llmrouter.RouterConfig{
		OpenAIKey:    cfg.OpenAIKey,
		AnthropicKey: cfg.AnthropicKey,
		GoogleKey:    cfg.GoogleKey,
		OllamaURL:    cfg.OllamaURL,
		DefaultModel: cfg.DefaultModel,
		OnPremMode:   cfg.OnPremMode,
	})

	r := chi.NewRouter()

	// Global middleware
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"chrome-extension://*", "https://*", "http://localhost:*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Org-Id", "X-API-Key"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Health check — unauthenticated, used by Docker health checks
	r.Get("/api/v1/health", handleHealth(cfg))

	// Extension API routes
	// Auth: API key required only when API_KEY env is set.
	// In development (API_KEY=""), all requests are allowed.
	r.Route("/api/v1", func(r chi.Router) {
		if cfg.APIKey != "" {
			r.Use(sentinelmw.APIKeyAuth(makeOrgLookup(cfg)))
		}
		r.Post("/scan", handleScan(cfg))
		r.Post("/events/batch", handleEventBatch())
		r.Get("/config", handleGetConfig(cfg))
	})

	// Dashboard API routes — always JWT-authenticated (stubs for Phase 3)
	r.Route("/api/v1/dashboard", func(r chi.Router) {
		r.Use(sentinelmw.JWTAuth(cfg.JWTSecret))
		r.Get("/policies", handleListPolicies())
		r.Post("/policies", handleCreatePolicy())
		r.Put("/policies/{id}", handleUpdatePolicy())
		r.Delete("/policies/{id}", handleDeletePolicy())
		r.Get("/analytics/user-risk", handleUserRiskScores())
		r.Get("/analytics/heatmap", handleRiskHeatmap())
		r.Get("/audit", handleAuditLog())
	})

	// LLM proxy — same auth as extension API
	r.Route("/proxy", func(r chi.Router) {
		if cfg.APIKey != "" {
			r.Use(sentinelmw.APIKeyAuth(makeOrgLookup(cfg)))
		}
		r.Post("/chat", handleProxyChat(cfg, llmRouter))
	})

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("[Sentinel] Starting proxy on :%s env=%s onprem=%v learning_mode=%v",
			cfg.Port, cfg.Environment, cfg.OnPremMode, cfg.LearningMode)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Sentinel] Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[Sentinel] Shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[Sentinel] Shutdown error: %v", err)
	}
}

// makeOrgLookup returns a lookup function for the middleware.
// Phase 1: validates against the API_KEY env var.
// Phase 2: replace with store.GetOrgByAPIKey(ctx, key).
func makeOrgLookup(cfg Config) sentinelmw.OrgLookupFunc {
	return func(ctx context.Context, key string) (string, error) {
		if key == cfg.APIKey {
			return cfg.DefaultOrgID, nil
		}
		return "", fmt.Errorf("invalid API key")
	}
}

// ============================================================
// HEALTH CHECK
// GET /api/v1/health
// ============================================================

func handleHealth(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]interface{}{
			"status":        "healthy",
			"version":       "0.3.0",
			"onprem":        cfg.OnPremMode,
			"learning_mode": cfg.LearningMode,
			"ml_service":    cfg.MLServiceURL,
		}, http.StatusOK)
	}
}

// ============================================================
// SCAN HANDLER — Core Detection Pipeline
// POST /api/v1/scan
//
// Flow: decode → regex scan → ML scan (optional) → policy eval
//       → apply learning mode → redact (if REDACT) → respond
// ============================================================

// scanRequest is the inbound body from the browser extension.
type scanRequest struct {
	Content      string `json:"content"`
	ContentType  string `json:"contentType"`
	TargetDomain string `json:"targetDomain"`
	TargetURL    string `json:"targetUrl"`
	Timestamp    string `json:"timestamp"`
}

// scanResponse is the outbound shape the extension expects.
// Must match TypeScript: { action, detections, combinedRisk, userMessage?, redactedContent? }
type scanResponse struct {
	Action           string             `json:"action"`
	Detections       []scanner.Detection `json:"detections"`
	CombinedRisk     string             `json:"combinedRisk"`
	ScanDurationMs   float64            `json:"scanDurationMs"`
	UserMessage      string             `json:"userMessage,omitempty"`
	RedactedContent  string             `json:"redactedContent,omitempty"`
}

func handleScan(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req scanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Empty content → nothing to detect
		if strings.TrimSpace(req.Content) == "" {
			jsonResponse(w, scanResponse{
				Action:       "LOG",
				Detections:   []scanner.Detection{},
				CombinedRisk: "LOW",
			}, http.StatusOK)
			return
		}

		// Step 1: Server-side regex scan (always runs, <5ms)
		scanResult := scanner.ScanText(req.Content, nil)

		// Ensure detections is always a JSON array, never null.
		if scanResult.Detections == nil {
			scanResult.Detections = make([]scanner.Detection, 0)
		}

		// Step 2: Optional ML service scan (additive — does not replace regex)
		// ML is non-blocking: if unavailable, regex results stand on their own.
		if cfg.MLServiceURL != "" {
			mlDetections := callMLService(cfg.MLServiceURL, req.Content)
			if len(mlDetections) > 0 {
				scanResult = scanner.MergeMLDetections(scanResult, mlDetections)
				log.Printf("[Sentinel] ML: merged %d detections domain=%s new_risk=%s",
					len(mlDetections), req.TargetDomain, scanResult.CombinedRisk)
			}
		}

		// Step 3: Policy engine evaluation
		// Phase 1: no org-specific rules (DB not wired). Scanner's action is the default.
		// Phase 2: load rules via store.GetPolicies(ctx, orgID) and pass them here.
		entityTypes := uniqueEntityTypes(scanResult.Detections)
		policyCtx := policy.EvalContext{
			EntityTypes:   entityTypes,
			AiTool:        req.TargetDomain,
			Sensitivity:   scanResult.CombinedRisk,
			MaxConfidence: maxConfidence(scanResult.Detections),
		}
		evalResult := policy.Evaluate([]policy.Rule{}, policyCtx, scanResult.RecommendedAction)
		action := evalResult.Action

		// Step 4: Learning mode is server-authoritative.
		// If learning mode is on, we report what we found but take no enforcement action.
		if cfg.LearningMode {
			action = "LOG"
		}

		resp := scanResponse{
			Action:         action,
			Detections:     scanResult.Detections,
			CombinedRisk:   scanResult.CombinedRisk,
			ScanDurationMs: scanResult.ScanDurationMs,
			UserMessage:    buildUserMessage(action, entityTypes, cfg.LearningMode),
		}

		// Step 5: If REDACT, produce the cleaned content for the extension to use.
		// The extension replaces the pasted/typed text with redactedContent.
		if action == "REDACT" && len(scanResult.Detections) > 0 {
			redactResult := redactor.RedactFromScanResult(req.Content, toRedactInput(scanResult.Detections))
			resp.RedactedContent = redactResult.RedactedText
		}

		log.Printf("[Sentinel] scan: domain=%s action=%s risk=%s detections=%d duration=%.2fms",
			req.TargetDomain, action, scanResult.CombinedRisk,
			len(scanResult.Detections), scanResult.ScanDurationMs)

		jsonResponse(w, resp, http.StatusOK)
	}
}

// ============================================================
// PROXY CHAT HANDLER — Scan → Redact → Route → Re-identify
// POST /proxy/chat
//
// Flow: decode → scan messages → policy → block? → redact? →
//       route to LLM → re-identify response → respond
// ============================================================

// chatMessage mirrors the router.Message type but carries json tags
// so it can be decoded from the HTTP request body.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func handleProxyChat(cfg Config, rt *llmrouter.Router) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Provider string        `json:"provider"`
			Model    string        `json:"model"`
			Messages []chatMessage `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if len(req.Messages) == 0 {
			jsonError(w, "No messages provided", http.StatusBadRequest)
			return
		}

		// Step 1: Scan all user and system messages combined.
		// We scan the combined text to catch PII that spans multiple messages,
		// but we redact per-message so offsets stay correct.
		combinedScan := scanMessages(req.Messages)

		// Step 2: Policy evaluation
		entityTypes := uniqueEntityTypes(combinedScan.Detections)
		policyCtx := policy.EvalContext{
			EntityTypes:   entityTypes,
			AiTool:        req.Provider,
			Sensitivity:   combinedScan.CombinedRisk,
			MaxConfidence: maxConfidence(combinedScan.Detections),
		}
		evalResult := policy.Evaluate([]policy.Rule{}, policyCtx, combinedScan.RecommendedAction)
		action := evalResult.Action

		if cfg.LearningMode {
			action = "LOG"
		}

		// Step 3: Hard block — reject before any data leaves
		if action == "BLOCK" {
			log.Printf("[Sentinel] /proxy/chat BLOCKED provider=%s risk=%s types=%v",
				req.Provider, combinedScan.CombinedRisk, entityTypes)
			jsonError(w, fmt.Sprintf(
				"Request blocked: %s detected (%s risk). Sensitive data cannot be forwarded to AI providers.",
				strings.Join(entityTypes, ", "), combinedScan.CombinedRisk,
			), http.StatusForbidden)
			return
		}

		// Step 4: Build router messages, redacting per-message when action is REDACT.
		// Mappings are kept in-memory for re-identification after the LLM responds.
		routerMessages, redactMappings := buildRouterMessages(req.Messages, action)

		// Step 5: Route to the appropriate LLM backend.
		// Router considers: on-prem mode, sensitivity level, requested provider.
		decision := rt.Decide(combinedScan.CombinedRisk, req.Provider, "")
		llmReq := llmrouter.LLMRequest{
			Provider: req.Provider,
			Model:    req.Model,
			Messages: routerMessages,
		}

		llmResp, err := rt.Forward(r.Context(), decision, llmReq)
		if err != nil {
			log.Printf("[Sentinel] LLM forward error provider=%s: %v", req.Provider, err)
			jsonError(w, fmt.Sprintf("LLM request failed: %v", err), http.StatusBadGateway)
			return
		}

		// Step 6: Re-identify placeholders in the LLM response.
		// Also run a hallucination check — warn if LLM reproduced original PII.
		responseContent := llmResp.Content
		if len(redactMappings) > 0 {
			leaked := redactor.ScanResponseForHallucinatedPII(responseContent, redactMappings)
			if len(leaked) > 0 {
				log.Printf("[Sentinel] WARNING: LLM response contains hallucinated PII types=%v provider=%s",
					leaked, req.Provider)
			}
			responseContent = redactor.ReIdentify(responseContent, redactMappings)
		}

		log.Printf("[Sentinel] /proxy/chat: provider=%s model=%s action=%s routed_to=%s tokens=%d",
			req.Provider, llmResp.Model, action, llmResp.RoutedTo, llmResp.TokensUsed)

		jsonResponse(w, map[string]interface{}{
			"content":    responseContent,
			"model":      llmResp.Model,
			"tokensUsed": llmResp.TokensUsed,
			"latencyMs":  llmResp.LatencyMs,
			"routedTo":   llmResp.RoutedTo,
			"action":     action,
		}, http.StatusOK)
	}
}

// scanMessages combines user + system message contents and scans them together.
func scanMessages(messages []chatMessage) scanner.ScanResult {
	var buf strings.Builder
	for _, m := range messages {
		if m.Role == "user" || m.Role == "system" {
			buf.WriteString(m.Content)
			buf.WriteByte('\n')
		}
	}
	content := buf.String()
	if strings.TrimSpace(content) == "" {
		return scanner.ScanResult{CombinedRisk: "LOW", RecommendedAction: "LOG"}
	}
	return scanner.ScanText(content, nil)
}

// buildRouterMessages converts chatMessages to router.Messages, redacting
// user/system messages individually when action == "REDACT".
// Returns the (possibly redacted) messages and all redaction mappings.
func buildRouterMessages(messages []chatMessage, action string) ([]llmrouter.Message, []redactor.Mapping) {
	out := make([]llmrouter.Message, len(messages))
	var mappings []redactor.Mapping

	for i, m := range messages {
		content := m.Content

		if action == "REDACT" && (m.Role == "user" || m.Role == "system") {
			msgScan := scanner.ScanText(m.Content, nil)
			if len(msgScan.Detections) > 0 {
				result := redactor.RedactFromScanResult(m.Content, toRedactInput(msgScan.Detections))
				content = result.RedactedText
				mappings = append(mappings, result.Mappings...)
			}
		}

		out[i] = llmrouter.Message{Role: m.Role, Content: content}
	}

	return out, mappings
}

// toRedactInput converts scanner.Detection slice to the anonymous struct type
// expected by redactor.RedactFromScanResult.
func toRedactInput(detections []scanner.Detection) []struct {
	EntityType  string
	MatchedText string
	StartOffset int
	EndOffset   int
} {
	input := make([]struct {
		EntityType  string
		MatchedText string
		StartOffset int
		EndOffset   int
	}, len(detections))
	for i, d := range detections {
		input[i].EntityType = d.EntityType
		input[i].MatchedText = d.MatchedText
		input[i].StartOffset = d.StartOffset
		input[i].EndOffset = d.EndOffset
	}
	return input
}

// uniqueEntityTypes returns deduplicated entity type strings from detections.
func uniqueEntityTypes(detections []scanner.Detection) []string {
	seen := make(map[string]struct{})
	var types []string
	for _, d := range detections {
		if _, ok := seen[d.EntityType]; !ok {
			seen[d.EntityType] = struct{}{}
			types = append(types, d.EntityType)
		}
	}
	return types
}

// maxConfidence returns the highest confidence value across all detections.
func maxConfidence(detections []scanner.Detection) float64 {
	var max float64
	for _, d := range detections {
		if d.Confidence > max {
			max = d.Confidence
		}
	}
	return max
}

// buildUserMessage constructs a human-readable UI message for the extension banner.
func buildUserMessage(action string, entityTypes []string, learningMode bool) string {
	if len(entityTypes) == 0 {
		return ""
	}
	types := strings.Join(entityTypes, ", ")
	if learningMode {
		return fmt.Sprintf("Learning Mode: %s detected — monitoring only, no action taken.", types)
	}
	switch action {
	case "BLOCK":
		return fmt.Sprintf("Blocked: %s detected. This content cannot be sent to AI tools.", types)
	case "REDACT":
		return fmt.Sprintf("Redacted: %s replaced with placeholders before sending.", types)
	case "WARN":
		return fmt.Sprintf("Warning: %s detected in content.", types)
	default:
		return fmt.Sprintf("Logged: %s detected.", types)
	}
}

// ============================================================
// ML SERVICE CLIENT (optional, additive)
// ============================================================

func callMLService(mlURL, text string) []map[string]interface{} {
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return nil
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(mlURL+"/api/v1/classify", "application/json",
		strings.NewReader(string(body)))
	if err != nil {
		// ML service is optional — absence is not an error
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var mlResp struct {
		Detections []map[string]interface{} `json:"detections"`
	}
	if err := json.Unmarshal(respBody, &mlResp); err != nil {
		return nil
	}
	return mlResp.Detections
}

// ============================================================
// EVENT BATCH HANDLER
// POST /api/v1/events/batch
// Phase 1: decode and log to stdout (not silently discarded).
// Phase 2: wire to store.InsertAuditEventBatch / InsertShadowAiEventBatch.
// ============================================================

func handleEventBatch() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var batch struct {
			AuditEvents    []json.RawMessage `json:"auditEvents"`
			ShadowAiEvents []json.RawMessage `json:"shadowAiEvents"`
		}
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			jsonError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		log.Printf("[Sentinel] Event batch: audit=%d shadow_ai=%d",
			len(batch.AuditEvents), len(batch.ShadowAiEvents))

		// Phase 2: persist via store.InsertAuditEventBatch(ctx, events)
		w.WriteHeader(http.StatusAccepted)
	}
}

// ============================================================
// CONFIG HANDLER
// GET /api/v1/config
// Returns the server-side config to the extension.
// Phase 2: return org-specific config from DB (by org ID from auth context).
// ============================================================

func handleGetConfig(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]interface{}{
			// learningMode is now env-driven, NOT hardcoded to true.
			"learningMode":            cfg.LearningMode,
			"enabledDetectors":        []string{"SSN", "CREDIT_CARD", "API_KEY", "AWS_KEY", "GCP_KEY", "EMAIL", "PHONE", "MEDICAL_ID", "CREDENTIALS", "SOURCE_CODE"},
			"aiDomainRegistryVersion": "1.0.0",
			"regexPatternsVersion":    "1.0.0",
			"onPremMode":              cfg.OnPremMode,
		}, http.StatusOK)
	}
}

// ============================================================
// DASHBOARD STUBS — Phase 3: wire to DB store
// All routes are JWT-protected (see main routing setup).
// ============================================================

func handleListPolicies() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]interface{}{"data": []interface{}{}}, http.StatusOK)
	}
}

func handleCreatePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}
}

func handleUpdatePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

func handleDeletePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleUserRiskScores() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]interface{}{"data": []interface{}{}}, http.StatusOK)
	}
}

func handleRiskHeatmap() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]interface{}{"data": []interface{}{}}, http.StatusOK)
	}
}

func handleAuditLog() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]interface{}{"data": []interface{}{}}, http.StatusOK)
	}
}

// ============================================================
// UTILITIES
// ============================================================

func jsonResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[Sentinel] jsonResponse encode error: %v", err)
	}
}

func jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"error": map[string]string{"message": message},
	})
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
