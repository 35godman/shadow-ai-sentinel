package router

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ============================================================
// LLM ROUTER
// Routes prompts to the appropriate LLM based on:
//   - Scan result (clean vs sensitive)
//   - Org settings (allowed/blocked tools, on-prem endpoint)
//   - Policy decision (forward, redact+forward, block)
// ============================================================

type RouteDecision struct {
	Target      string // "external", "onprem", "blocked"
	Provider    string // "openai", "anthropic", "google", "ollama"
	EndpointURL string
	Model       string
}

type LLMRequest struct {
	Provider    string
	Model       string
	Prompt      string
	Messages    []Message
	MaxTokens   int
	Temperature float64
	Stream      bool
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type LLMResponse struct {
	Content      string  `json:"content"`
	Model        string  `json:"model"`
	TokensUsed   int     `json:"tokensUsed,omitempty"`
	LatencyMs    float64 `json:"latencyMs"`
	RoutedTo     string  `json:"routedTo"` // "external" or "onprem"
}

type RouterConfig struct {
	OpenAIKey      string
	AnthropicKey   string
	GoogleKey      string
	OllamaURL      string // e.g. "http://ollama:11434"
	DefaultModel   string // Default on-prem model e.g. "llama3.1"
	OnPremMode     bool
	HTTPClient     *http.Client
}

func NewRouter(cfg RouterConfig) *Router {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 60 * time.Second}
	}
	return &Router{cfg: cfg}
}

type Router struct {
	cfg RouterConfig
}

// Decide determines where to route based on sensitivity and config
func (rt *Router) Decide(sensitivity string, targetProvider string, onPremEndpoint string) RouteDecision {
	// If on-prem mode, everything goes local
	if rt.cfg.OnPremMode {
		return RouteDecision{
			Target:      "onprem",
			Provider:    "ollama",
			EndpointURL: rt.cfg.OllamaURL,
			Model:       rt.cfg.DefaultModel,
		}
	}

	// If CRITICAL/HIGH sensitivity and on-prem available, route locally
	if (sensitivity == "CRITICAL" || sensitivity == "HIGH") && onPremEndpoint != "" {
		return RouteDecision{
			Target:      "onprem",
			Provider:    "ollama",
			EndpointURL: onPremEndpoint,
			Model:       rt.cfg.DefaultModel,
		}
	}

	// Otherwise, forward to the requested external provider
	switch targetProvider {
	case "openai", "chatgpt":
		return RouteDecision{
			Target:      "external",
			Provider:    "openai",
			EndpointURL: "https://api.openai.com/v1/chat/completions",
			Model:       "gpt-4o",
		}
	case "anthropic", "claude":
		return RouteDecision{
			Target:      "external",
			Provider:    "anthropic",
			EndpointURL: "https://api.anthropic.com/v1/messages",
			Model:       "claude-sonnet-4-20250514",
		}
	case "google", "gemini":
		return RouteDecision{
			Target:      "external",
			Provider:    "google",
			EndpointURL: "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent",
			Model:       "gemini-pro",
		}
	default:
		// Default to on-prem if available, otherwise OpenAI
		if rt.cfg.OllamaURL != "" {
			return RouteDecision{
				Target:      "onprem",
				Provider:    "ollama",
				EndpointURL: rt.cfg.OllamaURL,
				Model:       rt.cfg.DefaultModel,
			}
		}
		return RouteDecision{
			Target:      "external",
			Provider:    "openai",
			EndpointURL: "https://api.openai.com/v1/chat/completions",
			Model:       "gpt-4o",
		}
	}
}

// Forward sends the (possibly redacted) prompt to the target LLM
func (rt *Router) Forward(ctx context.Context, decision RouteDecision, req LLMRequest) (*LLMResponse, error) {
	start := time.Now()

	switch decision.Provider {
	case "openai":
		return rt.forwardOpenAI(ctx, decision, req, start)
	case "anthropic":
		return rt.forwardAnthropic(ctx, decision, req, start)
	case "ollama":
		return rt.forwardOllama(ctx, decision, req, start)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", decision.Provider)
	}
}

// ============================================================
// PROVIDER-SPECIFIC FORWARDING
// ============================================================

func (rt *Router) forwardOpenAI(ctx context.Context, decision RouteDecision, req LLMRequest, start time.Time) (*LLMResponse, error) {
	messages := req.Messages
	if len(messages) == 0 && req.Prompt != "" {
		messages = []Message{{Role: "user", Content: req.Prompt}}
	}

	body := map[string]interface{}{
		"model":       decision.Model,
		"messages":    messages,
		"max_tokens":  coalesce(req.MaxTokens, 2048),
		"temperature": req.Temperature,
	}

	respBody, err := rt.doHTTP(ctx, decision.EndpointURL, body, map[string]string{
		"Authorization": "Bearer " + rt.cfg.OpenAIKey,
	})
	if err != nil {
		return nil, fmt.Errorf("openai request: %w", err)
	}

	// Parse OpenAI response
	var oaiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &oaiResp); err != nil {
		return nil, fmt.Errorf("parse openai response: %w", err)
	}

	content := ""
	if len(oaiResp.Choices) > 0 {
		content = oaiResp.Choices[0].Message.Content
	}

	return &LLMResponse{
		Content:    content,
		Model:      decision.Model,
		TokensUsed: oaiResp.Usage.TotalTokens,
		LatencyMs:  float64(time.Since(start).Milliseconds()),
		RoutedTo:   decision.Target,
	}, nil
}

func (rt *Router) forwardAnthropic(ctx context.Context, decision RouteDecision, req LLMRequest, start time.Time) (*LLMResponse, error) {
	messages := req.Messages
	if len(messages) == 0 && req.Prompt != "" {
		messages = []Message{{Role: "user", Content: req.Prompt}}
	}

	body := map[string]interface{}{
		"model":      decision.Model,
		"messages":   messages,
		"max_tokens": coalesce(req.MaxTokens, 2048),
	}

	respBody, err := rt.doHTTP(ctx, decision.EndpointURL, body, map[string]string{
		"x-api-key":         rt.cfg.AnthropicKey,
		"anthropic-version": "2023-06-01",
	})
	if err != nil {
		return nil, fmt.Errorf("anthropic request: %w", err)
	}

	var claudeResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &claudeResp); err != nil {
		return nil, fmt.Errorf("parse anthropic response: %w", err)
	}

	content := ""
	if len(claudeResp.Content) > 0 {
		content = claudeResp.Content[0].Text
	}

	return &LLMResponse{
		Content:    content,
		Model:      decision.Model,
		TokensUsed: claudeResp.Usage.InputTokens + claudeResp.Usage.OutputTokens,
		LatencyMs:  float64(time.Since(start).Milliseconds()),
		RoutedTo:   decision.Target,
	}, nil
}

func (rt *Router) forwardOllama(ctx context.Context, decision RouteDecision, req LLMRequest, start time.Time) (*LLMResponse, error) {
	messages := req.Messages
	if len(messages) == 0 && req.Prompt != "" {
		messages = []Message{{Role: "user", Content: req.Prompt}}
	}

	body := map[string]interface{}{
		"model":    decision.Model,
		"messages": messages,
		"stream":   false,
	}

	endpoint := decision.EndpointURL + "/api/chat"
	respBody, err := rt.doHTTP(ctx, endpoint, body, nil)
	if err != nil {
		return nil, fmt.Errorf("ollama request: %w", err)
	}

	var ollamaResp struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		EvalCount int `json:"eval_count"`
	}
	if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
		return nil, fmt.Errorf("parse ollama response: %w", err)
	}

	return &LLMResponse{
		Content:    ollamaResp.Message.Content,
		Model:      decision.Model,
		TokensUsed: ollamaResp.EvalCount,
		LatencyMs:  float64(time.Since(start).Milliseconds()),
		RoutedTo:   "onprem",
	}, nil
}

// ============================================================
// HTTP HELPER
// ============================================================

func (rt *Router) doHTTP(ctx context.Context, url string, body interface{}, headers map[string]string) ([]byte, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := rt.cfg.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody[:min(len(respBody), 500)]))
	}

	return respBody, nil
}

func coalesce(val, fallback int) int {
	if val > 0 {
		return val
	}
	return fallback
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
