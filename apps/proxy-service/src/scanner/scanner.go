package scanner

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// ============================================================
// DETECTION TYPES
// ============================================================

type Detection struct {
	ID               string  `json:"id"`
	EntityType       string  `json:"entityType"`
	Confidence       float64 `json:"confidence"`
	Source           string  `json:"source"` // "REGEX" or "ML" or "COMBINED"
	MatchedText      string  `json:"matchedText"`
	RedactedText     string  `json:"redactedText"`
	ContextRiskScore string  `json:"contextRiskScore"` // LOW, MEDIUM, HIGH, CRITICAL
	StartOffset      int     `json:"startOffset"`
	EndOffset        int     `json:"endOffset"`
	PatternID        string  `json:"patternId,omitempty"`
}

type ScanResult struct {
	Detections        []Detection `json:"detections"`
	CombinedRisk      string      `json:"combinedRiskScore"`
	RecommendedAction string      `json:"recommendedAction"`
	ScanDurationMs    float64     `json:"scanDurationMs"`
	RegexDurationMs   float64     `json:"regexDurationMs"`
	MlDurationMs      *float64    `json:"mlDurationMs,omitempty"`
	Degraded          bool        `json:"degraded,omitempty"` // true when ML was skipped (circuit open / budget exhausted)
}

// ============================================================
// PATTERN DEFINITIONS
// ============================================================

type Pattern struct {
	ID                   string
	EntityType           string
	Name                 string
	Regex                *regexp.Regexp
	Validator            func(match string) bool
	SensitivityLevel     string
	ComplianceFrameworks []string
}

var Patterns = []Pattern{
	// --- SSN ---
	{
		ID: "ssn-dashed", EntityType: "SSN", Name: "US SSN (Dashed)",
		Regex: regexp.MustCompile(`\b(\d{3}-\d{2}-\d{4})\b`),
		Validator: validateSSN,
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"HIPAA", "SOC2", "CCPA"},
	},
	{
		ID: "ssn-nodash", EntityType: "SSN", Name: "US SSN (No Dash)",
		Regex: regexp.MustCompile(`\b(\d{9})\b`),
		Validator: validateSSN,
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"HIPAA", "SOC2", "CCPA"},
	},

	// --- Credit Cards ---
	{
		ID: "cc-visa", EntityType: "CREDIT_CARD", Name: "Visa",
		Regex: regexp.MustCompile(`\b(4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b`),
		Validator: luhnCheck,
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"PCI-DSS"},
	},
	{
		ID: "cc-mastercard", EntityType: "CREDIT_CARD", Name: "Mastercard",
		Regex: regexp.MustCompile(`\b(5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b`),
		Validator: luhnCheck,
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"PCI-DSS"},
	},
	{
		ID: "cc-amex", EntityType: "CREDIT_CARD", Name: "Amex",
		Regex: regexp.MustCompile(`\b(3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5})\b`),
		Validator: luhnCheck,
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"PCI-DSS"},
	},

	// --- API Keys ---
	{
		ID: "openai-key", EntityType: "API_KEY", Name: "OpenAI Key",
		Regex: regexp.MustCompile(`\b(sk-[a-zA-Z0-9_-]{20,})\b`),
		Validator: highEntropy,
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"SOC2"},
	},
	{
		ID: "anthropic-key", EntityType: "API_KEY", Name: "Anthropic Key",
		Regex: regexp.MustCompile(`\b(sk-ant-[a-zA-Z0-9_-]{20,})\b`),
		Validator: highEntropy,
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"SOC2"},
	},
	{
		ID: "github-token", EntityType: "API_KEY", Name: "GitHub PAT",
		Regex: regexp.MustCompile(`\b(ghp_[a-zA-Z0-9]{36,})\b`),
		SensitivityLevel: "HIGH", ComplianceFrameworks: []string{"SOC2"},
	},
	{
		ID: "github-oauth", EntityType: "API_KEY", Name: "GitHub OAuth Token",
		Regex: regexp.MustCompile(`\b(gho_[a-zA-Z0-9]{36,})\b`),
		SensitivityLevel: "HIGH", ComplianceFrameworks: []string{"SOC2"},
	},
	{
		ID: "slack-token", EntityType: "API_KEY", Name: "Slack Token",
		Regex: regexp.MustCompile(`\b(xox[bprs]-[a-zA-Z0-9-]{10,})\b`),
		SensitivityLevel: "HIGH", ComplianceFrameworks: []string{"SOC2"},
	},
	{
		ID: "stripe-key", EntityType: "API_KEY", Name: "Stripe Key",
		Regex: regexp.MustCompile(`\b([rs]k_(?:live|test)_[a-zA-Z0-9]{20,})\b`),
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"PCI-DSS", "SOC2"},
	},

	// --- Cloud Keys ---
	{
		ID: "aws-access-key", EntityType: "AWS_KEY", Name: "AWS Access Key",
		Regex: regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"SOC2", "CIS"},
	},
	{
		// AWS secret key: 40-char base64-like string with high entropy and mixed case+digits.
		ID: "aws-secret-key", EntityType: "AWS_KEY", Name: "AWS Secret Access Key",
		Regex: regexp.MustCompile(`\b([a-zA-Z0-9/+=]{40})\b`),
		Validator: awsSecretValidator,
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"SOC2", "CIS"},
	},
	{
		ID: "gcp-service-key", EntityType: "GCP_KEY", Name: "GCP Service Key",
		Regex: regexp.MustCompile(`"private_key":\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----`),
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"SOC2", "CIS"},
	},
	{
		// Google/Gemini API key: AIza prefix followed by 35 alphanumeric/dash/underscore chars.
		ID: "google-api-key", EntityType: "GCP_KEY", Name: "Google/Gemini API Key",
		Regex:            regexp.MustCompile(`\b(AIza[A-Za-z0-9\-_]{35})\b`),
		Validator:        highEntropy,
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"SOC2", "CIS"},
	},

	// --- PII ---
	{
		ID: "email", EntityType: "EMAIL", Name: "Email",
		Regex: regexp.MustCompile(`\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b`),
		SensitivityLevel: "MEDIUM", ComplianceFrameworks: []string{"GDPR", "CCPA"},
	},
	{
		ID: "phone-us", EntityType: "PHONE", Name: "US Phone",
		Regex:     regexp.MustCompile(`\b(\+?1?[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4})\b`),
		Validator: validatePhone,
		SensitivityLevel: "MEDIUM", ComplianceFrameworks: []string{"GDPR", "CCPA"},
	},
	{
		ID: "phone-intl", EntityType: "PHONE", Name: "International Phone",
		Regex:     regexp.MustCompile(`(\+[1-9]\d{1,2}[\s.\-]?\d{2,4}[\s.\-]?\d{3,4}[\s.\-]?\d{3,4})`),
		Validator: validateIntlPhone,
		SensitivityLevel: "MEDIUM", ComplianceFrameworks: []string{"GDPR", "CCPA"},
	},
	{
		ID: "ipv4-private", EntityType: "IP_ADDRESS", Name: "Private IP",
		Regex: regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
		SensitivityLevel: "MEDIUM", ComplianceFrameworks: []string{"SOC2"},
	},

	// --- Medical ---
	{
		ID: "npi", EntityType: "MEDICAL_ID", Name: "NPI",
		Regex: regexp.MustCompile(`(?i)\b(NPI[:\s#]*\d{10})\b`),
		SensitivityLevel: "HIGH", ComplianceFrameworks: []string{"HIPAA"},
	},
	{
		// Requires a medical context prefix to avoid matching version numbers, model IDs, etc.
		ID: "icd10", EntityType: "DIAGNOSIS", Name: "ICD-10",
		Regex: regexp.MustCompile(`(?i)\b(?:ICD|DX|diagnosis|code)[-:\s]*([A-TV-Z]\d{2}(?:\.\d{1,4})?)\b`),
		SensitivityLevel: "HIGH", ComplianceFrameworks: []string{"HIPAA"},
	},
	{
		ID: "dea-number", EntityType: "MEDICAL_ID", Name: "DEA Number",
		Regex: regexp.MustCompile(`(?i)\b(DEA[:\s#]*[A-Z]{2}\d{7})\b`),
		SensitivityLevel: "HIGH", ComplianceFrameworks: []string{"HIPAA"},
	},

	// --- Financial ---
	{
		ID: "iban", EntityType: "IBAN", Name: "IBAN",
		Regex: regexp.MustCompile(`\b([A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?(?:[A-Z0-9]{4}[\s]?){1,7}[A-Z0-9]{1,4})\b`),
		SensitivityLevel: "HIGH", ComplianceFrameworks: []string{"PCI-DSS", "GDPR"},
	},
	{
		// Requires context keyword to avoid matching bare 9-digit numbers.
		ID: "routing-number", EntityType: "FINANCIAL_ACCOUNT", Name: "US Routing Number",
		Regex: regexp.MustCompile(`(?i)\b((?:routing|aba|rtn)[:\s#]*\d{9})\b`),
		SensitivityLevel: "HIGH", ComplianceFrameworks: []string{"PCI-DSS"},
	},

	// --- Secrets ---
	{
		// Requires user:pass@ to avoid flagging bare connection strings without credentials.
		ID: "connection-string", EntityType: "CREDENTIALS", Name: "DB Connection String",
		Regex: regexp.MustCompile(`((?:mongodb|postgres|mysql|redis|amqp):\/\/[^:\s'"]+:[^@\s'"]+@[^\s'"]+)`),
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"SOC2"},
	},
	{
		ID: "private-key", EntityType: "CREDENTIALS", Name: "Private Key",
		Regex: regexp.MustCompile(`(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)`),
		SensitivityLevel: "CRITICAL", ComplianceFrameworks: []string{"SOC2", "CIS"},
	},

	// --- Source Code ---
	{
		ID: "code-function-py", EntityType: "SOURCE_CODE", Name: "Python Function",
		Regex: regexp.MustCompile(`\b(def\s+[a-zA-Z_]\w*\s*\([^)]*\)\s*(?:->[\s\w\[\],]*)?:)`),
		SensitivityLevel: "MEDIUM", ComplianceFrameworks: []string{"IP"},
	},
	{
		ID: "code-function-js", EntityType: "SOURCE_CODE", Name: "JS/TS Function",
		Regex: regexp.MustCompile(`\b((?:export\s+)?(?:async\s+)?function\s+[a-zA-Z_]\w*\s*\([^)]*\))`),
		SensitivityLevel: "MEDIUM", ComplianceFrameworks: []string{"IP"},
	},
	{
		ID: "code-class", EntityType: "SOURCE_CODE", Name: "Class Definition",
		Regex: regexp.MustCompile(`\b((?:export\s+)?class\s+[A-Z]\w*(?:\s+extends\s+\w+)?(?:\s+implements\s+\w+)?\s*\{)`),
		SensitivityLevel: "MEDIUM", ComplianceFrameworks: []string{"IP"},
	},
	{
		ID: "code-import", EntityType: "SOURCE_CODE", Name: "Import Statement",
		Regex: regexp.MustCompile(`\b(import\s+(?:\{[^}]+\}\s+from\s+|[\w*]+\s+from\s+)?['"][^'"]+['"])`),
		SensitivityLevel: "LOW", ComplianceFrameworks: []string{"IP"},
	},
}

// ============================================================
// SCAN ENGINE
// ============================================================

func ScanText(text string, enabledTypes []string) ScanResult {
	start := time.Now()

	enabledSet := make(map[string]bool)
	for _, t := range enabledTypes {
		enabledSet[t] = true
	}

	seen := make(map[string]bool) // dedup by offset range
	var detections []Detection

	for _, p := range Patterns {
		if len(enabledTypes) > 0 && !enabledSet[p.EntityType] {
			continue
		}

		matches := p.Regex.FindAllStringSubmatchIndex(text, -1)
		for _, loc := range matches {
			// loc[0], loc[1] = full match byte positions; loc[2], loc[3] = capture group 1
			byteStart, byteEnd := loc[0], loc[1]
			matchText := text[byteStart:byteEnd]

			// Use capture group if available
			if len(loc) >= 4 && loc[2] >= 0 {
				matchText = text[loc[2]:loc[3]]
			}

			// Run validator
			if p.Validator != nil && !p.Validator(matchText) {
				continue
			}

			// Convert byte offsets to rune (character) offsets for Unicode safety.
			// Go's regexp returns byte positions; the redactor works with rune positions.
			runeStart := utf8.RuneCountInString(text[:byteStart])
			runeEnd := utf8.RuneCountInString(text[:byteEnd])

			// Dedup: use rune-based offsets as the key (fixes the string(rune(int)) bug
			// which converted integers to Unicode codepoints instead of their decimal string).
			key := fmt.Sprintf("%d-%d", runeStart, runeEnd)
			if seen[key] {
				continue
			}
			seen[key] = true

			detections = append(detections, Detection{
				ID:               fmt.Sprintf("%s-%d", p.ID, runeStart),
				EntityType:       p.EntityType,
				Confidence:       0.95,
				Source:           "REGEX",
				MatchedText:      matchText,
				RedactedText:     "[" + p.EntityType + "_REDACTED]",
				ContextRiskScore: p.SensitivityLevel,
				StartOffset:      runeStart,
				EndOffset:        runeEnd,
				PatternID:        p.ID,
			})
		}
	}

	elapsed := time.Since(start).Seconds() * 1000

	combinedRisk := determineCombinedRisk(detections)
	action := DetermineAction(combinedRisk)

	return ScanResult{
		Detections:        detections,
		CombinedRisk:      combinedRisk,
		RecommendedAction: action,
		ScanDurationMs:    elapsed,
		RegexDurationMs:   elapsed,
	}
}

// ============================================================
// VALIDATORS
// ============================================================

func luhnCheck(num string) bool {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, num)

	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func validateSSN(ssn string) bool {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, ssn)

	if len(digits) != 9 {
		return false
	}

	area := int(digits[0]-'0')*100 + int(digits[1]-'0')*10 + int(digits[2]-'0')
	group := int(digits[3]-'0')*10 + int(digits[4]-'0')
	serial := int(digits[5]-'0')*1000 + int(digits[6]-'0')*100 + int(digits[7]-'0')*10 + int(digits[8]-'0')

	if area == 0 || area == 666 || area >= 900 {
		return false
	}
	if group == 0 || serial == 0 {
		return false
	}
	if digits == "123456789" || digits == "000000000" {
		return false
	}
	return true
}

func shannonEntropy(s string) float64 {
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	entropy := 0.0
	l := float64(len(s))
	for _, count := range freq {
		p := float64(count) / l
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func highEntropy(match string) bool {
	// Strip known prefixes
	clean := match
	for _, prefix := range []string{"sk-", "AKIA", "ghp_", "xoxb-", "xoxp-", "sk-ant-"} {
		clean = strings.TrimPrefix(clean, prefix)
	}
	return shannonEntropy(clean) > 3.5 && len(clean) >= 16
}

func validatePhone(phone string) bool {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, phone)
	return len(digits) >= 10 && len(digits) <= 11
}

func validateIntlPhone(phone string) bool {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, phone)
	return len(digits) >= 7 && len(digits) <= 15
}

// awsSecretValidator returns true only for high-entropy 40-char strings with
// mixed upper/lower/digit characters — characteristics of real AWS secret keys.
func awsSecretValidator(match string) bool {
	if len(match) != 40 {
		return false
	}
	hasUpper := strings.ContainsAny(match, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	hasLower := strings.ContainsAny(match, "abcdefghijklmnopqrstuvwxyz")
	hasDigit := strings.ContainsAny(match, "0123456789")
	return shannonEntropy(match) > 4.5 && hasUpper && hasLower && hasDigit
}

// ============================================================
// PROBABILISTIC FUSION — Bayesian ML + Regex Combination
// ============================================================

// entityFusionWeights maps entity types to [regexWeight, mlWeight].
// Weights calibrate each source's reliability per entity class.
//   - Structured entities (SSN, CC): regex is highly precise (Luhn, validators)
//   - Unstructured entities (PERSON, ORG): ML (spaCy NER) is authoritative
//   - Default: balanced trust in both sources
var entityFusionWeights = map[string][2]float64{
	"SSN":               {1.0, 0.6},
	"CREDIT_CARD":       {1.0, 0.6},
	"AWS_KEY":           {1.0, 0.4},
	"GCP_KEY":           {1.0, 0.4},
	"API_KEY":           {1.0, 0.4},
	"PERSON":            {0.5, 1.0},
	"ORGANIZATION":      {0.4, 1.0},
	"LOCATION":          {0.4, 1.0},
	"MEDICAL_CONDITION": {0.3, 1.0},
	"DIAGNOSIS":         {0.3, 1.0},
	"MEDICAL_ID":        {0.8, 0.9},
	"EMAIL":             {0.9, 0.7},
	"PHONE":             {0.8, 0.7},
	"IP_ADDRESS":        {0.9, 0.5},
	"IBAN":              {0.9, 0.6},
	"FINANCIAL_ACCOUNT": {0.9, 0.6},
	"CREDENTIALS":       {1.0, 0.5},
	"SOURCE_CODE":       {0.8, 0.6},
}

var defaultFusionWeights = [2]float64{0.8, 0.8}

// FuseConfidence combines regex and ML confidence using weighted Naïve Bayes
// independence assumption:
//
//	P_combined = 1 − (1 − w_regex × P_regex) × (1 − w_ml × P_ml)
//
// This is mathematically correct under the assumption that regex and ML are
// independent detectors. The weights calibrate each source's reliability.
func FuseConfidence(regexConf, mlConf float64, entityType string) float64 {
	w := entityFusionWeights[entityType]
	if w == [2]float64{} {
		w = defaultFusionWeights
	}
	combined := 1.0 - (1.0-w[0]*regexConf)*(1.0-w[1]*mlConf)
	if combined > 1.0 {
		combined = 1.0
	}
	return combined
}

// parseMLDetection extracts fields from a raw ML detection map.
func parseMLDetection(raw map[string]interface{}) (entityType string, start, end int, confidence float64, riskScore, matchedText, redactedText string) {
	entityType, _ = raw["entity_type"].(string)
	matchedText, _ = raw["text"].(string)
	startRaw, _ := raw["start"].(float64)
	endRaw, _ := raw["end"].(float64)
	confidence, _ = raw["confidence"].(float64)
	riskScore, _ = raw["context_risk_score"].(string)
	redactedText, _ = raw["redacted_text"].(string)

	start = int(startRaw)
	end = int(endRaw)

	if riskScore == "" {
		riskScore = "MEDIUM"
	}
	if redactedText == "" && entityType != "" {
		redactedText = "[" + entityType + "_REDACTED]"
	}
	return
}

// sensitivityRank returns a numeric rank for risk levels (higher = more severe).
func sensitivityRank(level string) int {
	switch strings.ToUpper(level) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// FuseMLDetections performs probabilistic fusion of regex and ML results.
//
// For overlapping detections of the same entity type:
//   - Combines confidences using weighted Naïve Bayes
//   - Sets Source to "COMBINED"
//   - Takes the higher risk score
//
// For non-overlapping ML detections: added as ML-source with original confidence.
//
// This replaces the old MergeMLDetections which simply discarded overlapping ML results.
func FuseMLDetections(base ScanResult, mlDets []map[string]interface{}) ScanResult {
	for _, raw := range mlDets {
		entityType, start, end, mlConf, riskScore, matchedText, redactedText := parseMLDetection(raw)
		if entityType == "" {
			continue
		}

		// Find overlapping regex detection of the same entity type
		overlapIdx := -1
		for i, existing := range base.Detections {
			if start < existing.EndOffset && end > existing.StartOffset {
				// Same entity type → fuse; different entity type → add separately
				if strings.EqualFold(existing.EntityType, entityType) {
					overlapIdx = i
				}
				break
			}
		}

		if overlapIdx >= 0 {
			// FUSION: combine confidences using weighted Naïve Bayes
			regexConf := base.Detections[overlapIdx].Confidence
			combined := FuseConfidence(regexConf, mlConf, entityType)
			base.Detections[overlapIdx].Confidence = combined
			base.Detections[overlapIdx].Source = "COMBINED"

			// Take the higher risk score
			if sensitivityRank(riskScore) > sensitivityRank(base.Detections[overlapIdx].ContextRiskScore) {
				base.Detections[overlapIdx].ContextRiskScore = riskScore
			}
		} else {
			// Non-overlapping: add ML detection as new entry
			base.Detections = append(base.Detections, Detection{
				ID:               fmt.Sprintf("ml-%s-%d", entityType, start),
				EntityType:       entityType,
				Confidence:       mlConf,
				Source:           "ML",
				MatchedText:      matchedText,
				RedactedText:     redactedText,
				ContextRiskScore: riskScore,
				StartOffset:      start,
				EndOffset:        end,
			})
		}
	}

	// Re-compute risk and action after fusion.
	base.CombinedRisk = determineCombinedRisk(base.Detections)
	base.RecommendedAction = DetermineAction(base.CombinedRisk)

	return base
}

// MergeMLDetections is kept for backward compatibility with existing callers.
// New code should use FuseMLDetections.
func MergeMLDetections(base ScanResult, mlDets []map[string]interface{}) ScanResult {
	return FuseMLDetections(base, mlDets)
}

// ============================================================
// RISK SCORING
// ============================================================

func determineCombinedRisk(detections []Detection) string {
	if len(detections) == 0 {
		return "LOW"
	}
	for _, d := range detections {
		if d.ContextRiskScore == "CRITICAL" {
			return "CRITICAL"
		}
	}
	for _, d := range detections {
		if d.ContextRiskScore == "HIGH" {
			return "HIGH"
		}
	}
	for _, d := range detections {
		if d.ContextRiskScore == "MEDIUM" {
			return "MEDIUM"
		}
	}
	return "LOW"
}

// DetermineAction maps a combined risk level to a policy action.
func DetermineAction(risk string) string {
	switch risk {
	case "CRITICAL":
		return "BLOCK"
	case "HIGH":
		return "REDACT"
	case "MEDIUM":
		return "WARN"
	default:
		return "LOG"
	}
}
