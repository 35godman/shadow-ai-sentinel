package router

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// Forward sends the (possibly redacted) prompt to the target LLM.
// If req.Model is non-empty, it overrides the model chosen by Decide().
func (rt *Router) Forward(ctx context.Context, decision RouteDecision, req LLMRequest) (*LLMResponse, error) {
	start := time.Now()

	// Allow the caller to override the routed model with a specific requested model.
	if req.Model != "" {
		decision.Model = req.Model
	}

	switch decision.Provider {
	case "openai":
		return rt.forwardOpenAI(ctx, decision, req, start)
	case "anthropic":
		return rt.forwardAnthropic(ctx, decision, req, start)
	case "google":
		return rt.forwardGoogle(ctx, decision, req, start)
	case "ollama":
		return rt.forwardOllama(ctx, decision, req, start)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", decision.Provider)
	}
}

// ============================================================
// STREAMING FORWARD — SSE pipe from LLM to client
// ============================================================

// RedactMapping mirrors redactor.Mapping for re-identification in streaming responses.
type RedactMapping struct {
	Placeholder string
	Original    string
}

// ForwardStream sends a streaming request to the LLM and pipes SSE chunks
// directly to the client writer. Performs re-identification on each chunk.
//
// Pre-scan enforcement must happen BEFORE calling this method.
func (rt *Router) ForwardStream(ctx context.Context, decision RouteDecision, req LLMRequest, w io.Writer, flusher http.Flusher, mappings interface{}) error {
	if req.Model != "" {
		decision.Model = req.Model
	}

	// Build provider-specific streaming request.
	var endpoint string
	var body interface{}
	var headers map[string]string

	switch decision.Provider {
	case "openai", "chatgpt":
		messages := req.Messages
		if len(messages) == 0 && req.Prompt != "" {
			messages = []Message{{Role: "user", Content: req.Prompt}}
		}
		body = map[string]interface{}{
			"model":       decision.Model,
			"messages":    messages,
			"max_tokens":  coalesce(req.MaxTokens, 2048),
			"temperature": req.Temperature,
			"stream":      true,
		}
		endpoint = decision.EndpointURL
		headers = map[string]string{
			"Authorization": "Bearer " + rt.cfg.OpenAIKey,
		}
	case "anthropic", "claude":
		messages := req.Messages
		if len(messages) == 0 && req.Prompt != "" {
			messages = []Message{{Role: "user", Content: req.Prompt}}
		}
		body = map[string]interface{}{
			"model":      decision.Model,
			"messages":   messages,
			"max_tokens": coalesce(req.MaxTokens, 2048),
			"stream":     true,
		}
		endpoint = decision.EndpointURL
		headers = map[string]string{
			"x-api-key":         rt.cfg.AnthropicKey,
			"anthropic-version": "2023-06-01",
		}
	case "ollama":
		messages := req.Messages
		if len(messages) == 0 && req.Prompt != "" {
			messages = []Message{{Role: "user", Content: req.Prompt}}
		}
		body = map[string]interface{}{
			"model":    decision.Model,
			"messages": messages,
			"stream":   true,
		}
		endpoint = decision.EndpointURL + "/api/chat"
		headers = nil
	default:
		return fmt.Errorf("streaming not supported for provider: %s", decision.Provider)
	}

	// Make the streaming HTTP request.
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal stream request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("create stream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := rt.cfg.HTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("stream request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("stream HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	// Pipe SSE chunks from LLM to client.
	// Re-identify placeholders in each chunk if mappings exist.
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		// Re-identify placeholders in data lines.
		if strings.HasPrefix(line, "data: ") {
			line = reidentifySSELine(line, mappings)
		}

		fmt.Fprintf(w, "%s\n", line)
		flusher.Flush()
	}

	// Send final done event.
	fmt.Fprintf(w, "data: {\"done\": true, \"routedTo\": %q}\n\n", decision.Target)
	flusher.Flush()

	return scanner.Err()
}

// reidentifySSELine replaces redaction placeholders in a streamed SSE data line.
func reidentifySSELine(line string, mappingsRaw interface{}) string {
	// Accept []RedactMapping or any slice of structs with Placeholder/Original.
	type mapping interface {
		GetPlaceholder() string
		GetOriginal() string
	}

	// Try the common redactor.Mapping shape via JSON-compatible interface.
	type simpleMapping struct {
		Placeholder string
		Original    string
	}

	// Use type assertion for the most common case.
	switch m := mappingsRaw.(type) {
	case []RedactMapping:
		for _, rm := range m {
			line = strings.ReplaceAll(line, rm.Placeholder, rm.Original)
		}
	case []simpleMapping:
		for _, rm := range m {
			line = strings.ReplaceAll(line, rm.Placeholder, rm.Original)
		}
	}
	// If mappings are of an unknown type or nil, return line unchanged.
	return line
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

func (rt *Router) forwardGoogle(ctx context.Context, decision RouteDecision, req LLMRequest, start time.Time) (*LLMResponse, error) {
	messages := req.Messages
	if len(messages) == 0 && req.Prompt != "" {
		messages = []Message{{Role: "user", Content: req.Prompt}}
	}

	// Convert messages to Gemini "contents" format.
	// Gemini uses "model" for the assistant role.
	type part struct {
		Text string `json:"text"`
	}
	type content struct {
		Role  string `json:"role"`
		Parts []part `json:"parts"`
	}
	contents := make([]content, 0, len(messages))
	for _, m := range messages {
		role := m.Role
		if role == "assistant" {
			role = "model"
		}
		contents = append(contents, content{
			Role:  role,
			Parts: []part{{Text: m.Content}},
		})
	}

	body := map[string]interface{}{
		"contents": contents,
		"generationConfig": map[string]interface{}{
			"maxOutputTokens": coalesce(req.MaxTokens, 2048),
			"temperature":     req.Temperature,
		},
	}

	// Gemini uses the API key as a URL parameter, not in Authorization header.
	endpoint := decision.EndpointURL + "?key=" + rt.cfg.GoogleKey

	respBody, err := rt.doHTTP(ctx, endpoint, body, nil)
	if err != nil {
		return nil, fmt.Errorf("google request: %w", err)
	}

	var geminiResp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		UsageMetadata struct {
			TotalTokenCount int `json:"totalTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(respBody, &geminiResp); err != nil {
		return nil, fmt.Errorf("parse google response: %w", err)
	}

	content2 := ""
	if len(geminiResp.Candidates) > 0 && len(geminiResp.Candidates[0].Content.Parts) > 0 {
		content2 = geminiResp.Candidates[0].Content.Parts[0].Text
	}

	return &LLMResponse{
		Content:    content2,
		Model:      decision.Model,
		TokensUsed: geminiResp.UsageMetadata.TotalTokenCount,
		LatencyMs:  float64(time.Since(start).Milliseconds()),
		RoutedTo:   decision.Target,
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
