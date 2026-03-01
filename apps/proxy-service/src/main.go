package main

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
)

// ============================================================
// CONFIG
// ============================================================

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
	DefaultModel string
}

func loadConfig() Config {
	return Config{
		Port:         getEnv("PORT", "8080"),
		DatabaseURL:  getEnv("DATABASE_URL", "postgres://sentinel:sentinel-dev-password@localhost:5432/sentinel?sslmode=disable"),
		RedisURL:     getEnv("REDIS_URL", "redis://:sentinel-dev-redis@localhost:6379"),
		MLServiceURL: getEnv("ML_SERVICE_URL", "http://localhost:8081"),
		OllamaURL:    getEnv("OLLAMA_URL", "http://localhost:11434"),
		JWTSecret:    getEnv("JWT_SECRET", "dev-secret-change-in-production"),
		OnPremMode:   getEnv("ONPREM_MODE", "false") == "true",
		Environment:  getEnv("ENVIRONMENT", "development"),
		OpenAIKey:    getEnv("OPENAI_API_KEY", ""),
		AnthropicKey: getEnv("ANTHROPIC_API_KEY", ""),
		DefaultModel: getEnv("DEFAULT_ONPREM_MODEL", "llama3.1"),
	}
}

// ============================================================
// MAIN
// ============================================================

func main() {
	cfg := loadConfig()

	r := chi.NewRouter()

	// Middleware
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

	// Health (unauthenticated)
	r.Get("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"healthy","version":"0.2.0","onprem":%v,"ml_service":"%s"}`, cfg.OnPremMode, cfg.MLServiceURL)
	})

	// Extension API routes
	r.Route("/api/v1", func(r chi.Router) {
		// TODO: Wire auth middleware with DB org lookup
		// r.Use(middleware.APIKeyAuth(orgLookup))

		r.Post("/scan", handleScan(cfg))
		r.Post("/events/batch", handleEventBatch())
		r.Get("/config", handleGetConfig(cfg))
	})

	// Dashboard API routes
	r.Route("/api/v1/dashboard", func(r chi.Router) {
		// TODO: Wire JWT auth middleware
		r.Get("/policies", handleListPolicies())
		r.Post("/policies", handleCreatePolicy())
		r.Put("/policies/{id}", handleUpdatePolicy())
		r.Delete("/policies/{id}", handleDeletePolicy())
		r.Get("/analytics/user-risk", handleUserRiskScores())
		r.Get("/analytics/heatmap", handleRiskHeatmap())
		r.Get("/audit", handleAuditLog())
	})

	// LLM proxy routes
	r.Route("/proxy", func(r chi.Router) {
		r.Post("/chat", handleProxyChat(cfg))
	})

	// Server
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("[Sentinel Proxy] Starting on :%s (onprem=%v, env=%s)", cfg.Port, cfg.OnPremMode, cfg.Environment)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[Sentinel Proxy] Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

// ============================================================
// SCAN HANDLER — Core Pipeline
// ============================================================

func handleScan(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Content      string `json:"content"`
			ContentType  string `json:"contentType"`
			TargetDomain string `json:"targetDomain"`
			TargetURL    string `json:"targetUrl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Step 1: Server-side regex scan (uses scanner package)
		// For now, inline a simplified version until Go modules are wired
		detections := []map[string]interface{}{}
		combinedRisk := "LOW"

		// Call ML service
		mlDetections := callMLService(cfg.MLServiceURL, req.Content)
		if len(mlDetections) > 0 {
			detections = append(detections, mlDetections...)
			combinedRisk = "MEDIUM" // Will be properly computed once scanner is imported
		}

		action := "LOG" // Default to learning mode

		jsonResponse(w, map[string]interface{}{
			"action":     action,
			"detections": detections,
			"combinedRisk": combinedRisk,
			"userMessage": func() string {
				if len(detections) > 0 {
					return fmt.Sprintf("Learning Mode: %d sensitive item(s) detected.", len(detections))
				}
				return ""
			}(),
		}, http.StatusOK)
	}
}

// ============================================================
// ML SERVICE CLIENT
// ============================================================

func callMLService(mlURL, text string) []map[string]interface{} {
	body, _ := json.Marshal(map[string]string{"text": text})
	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Post(mlURL+"/api/v1/classify", "application/json", strings.NewReader(string(body)))
	if err != nil {
		log.Printf("ML service unavailable: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	respBody, _ := io.ReadAll(resp.Body)
	var mlResp struct {
		Detections []map[string]interface{} `json:"detections"`
	}
	json.Unmarshal(respBody, &mlResp)
	return mlResp.Detections
}

// ============================================================
// PROXY CHAT HANDLER
// ============================================================

func handleProxyChat(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Provider string `json:"provider"`
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Determine target
		var targetURL, authHeader string
		switch req.Provider {
		case "ollama":
			targetURL = cfg.OllamaURL + "/api/chat"
			// No auth needed for local Ollama
		case "openai":
			targetURL = "https://api.openai.com/v1/chat/completions"
			authHeader = "Bearer " + cfg.OpenAIKey
		case "anthropic":
			targetURL = "https://api.anthropic.com/v1/messages"
			authHeader = cfg.AnthropicKey
		default:
			if cfg.OnPremMode {
				targetURL = cfg.OllamaURL + "/api/chat"
			} else {
				jsonError(w, "Unsupported provider", http.StatusBadRequest)
				return
			}
		}

		// Forward request
		forwardBody, _ := json.Marshal(map[string]interface{}{
			"model":    req.Model,
			"messages": req.Messages,
			"stream":   false,
		})

		httpReq, _ := http.NewRequestWithContext(r.Context(), "POST", targetURL, strings.NewReader(string(forwardBody)))
		httpReq.Header.Set("Content-Type", "application/json")
		if authHeader != "" {
			if req.Provider == "anthropic" {
				httpReq.Header.Set("x-api-key", authHeader)
				httpReq.Header.Set("anthropic-version", "2023-06-01")
			} else {
				httpReq.Header.Set("Authorization", authHeader)
			}
		}

		client := &http.Client{Timeout: 60 * time.Second}
		resp, err := client.Do(httpReq)
		if err != nil {
			jsonError(w, fmt.Sprintf("LLM request failed: %v", err), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Pass through response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

// ============================================================
// EVENT BATCH
// ============================================================

func handleEventBatch() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: Wire to store.InsertAuditEventBatch / InsertShadowAiEventBatch
		// For now, just accept
		w.WriteHeader(http.StatusAccepted)
	}
}

// ============================================================
// CONFIG
// ============================================================

func handleGetConfig(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]interface{}{
			"learningMode":           true,
			"enabledDetectors":       []string{"SSN", "CREDIT_CARD", "API_KEY", "AWS_KEY", "EMAIL", "PHONE", "MEDICAL_ID", "CREDENTIALS", "SOURCE_CODE"},
			"aiDomainRegistryVersion": "1.0.0",
			"regexPatternsVersion":   "1.0.0",
			"onPremMode":             cfg.OnPremMode,
		}, http.StatusOK)
	}
}

// ============================================================
// DASHBOARD STUBS (will wire to DB in Phase 3)
// ============================================================

func handleListPolicies() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]interface{}{"data": []interface{}{}}, http.StatusOK)
	}
}
func handleCreatePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusCreated) }
}
func handleUpdatePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
}
func handleDeletePolicy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
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
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"message": message}})
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
