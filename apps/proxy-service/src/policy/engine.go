package policy

import (
	"encoding/json"
	"strings"
)

// ============================================================
// POLICY ENGINE
// Evaluates IF/THEN rules against detection results.
// Rules are defined per-org in the database via the admin dashboard.
// ============================================================

type Rule struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Priority    int         `json:"priority"`
	Conditions  []Condition `json:"conditions"`
	Action      string      `json:"action"` // LOG, WARN, REDACT, BLOCK
	NotifyAdmin bool        `json:"notifyAdmin"`
	NotifyUser  bool        `json:"notifyUser"`
}

type Condition struct {
	Field    string      `json:"field"`    // entity_type, ai_tool, user_department, sensitivity, confidence
	Operator string      `json:"operator"` // equals, in, greater_than, less_than
	Value    interface{} `json:"value"`
}

type EvalContext struct {
	EntityTypes    []string // Entity types found in scan
	AiTool         string   // Target AI tool domain
	UserDepartment string   // User's department
	Sensitivity    string   // Combined risk score: LOW, MEDIUM, HIGH, CRITICAL
	MaxConfidence  float64  // Highest detection confidence
}

type EvalResult struct {
	MatchedRule *Rule  `json:"matchedRule,omitempty"`
	Action      string `json:"action"`      // Final action to take
	NotifyAdmin bool   `json:"notifyAdmin"`
	NotifyUser  bool   `json:"notifyUser"`
}

// Evaluate runs all rules (sorted by priority) and returns the first matching rule.
// If no rules match, returns the org default action.
func Evaluate(rules []Rule, ctx EvalContext, defaultAction string) EvalResult {
	// Rules should already be sorted by priority ASC (lower = higher priority)
	for _, rule := range rules {
		if matchesAllConditions(rule.Conditions, ctx) {
			return EvalResult{
				MatchedRule: &rule,
				Action:      rule.Action,
				NotifyAdmin: rule.NotifyAdmin,
				NotifyUser:  rule.NotifyUser,
			}
		}
	}

	// No rule matched — use default
	return EvalResult{
		Action:      defaultAction,
		NotifyAdmin: false,
		NotifyUser:  false,
	}
}

func matchesAllConditions(conditions []Condition, ctx EvalContext) bool {
	for _, c := range conditions {
		if !matchCondition(c, ctx) {
			return false
		}
	}
	return true
}

func matchCondition(c Condition, ctx EvalContext) bool {
	switch c.Field {
	case "entity_type":
		return matchEntityType(c, ctx.EntityTypes)
	case "ai_tool":
		return matchString(c, ctx.AiTool)
	case "user_department":
		return matchString(c, ctx.UserDepartment)
	case "sensitivity":
		return matchSensitivity(c, ctx.Sensitivity)
	case "confidence":
		return matchFloat(c, ctx.MaxConfidence)
	default:
		return false
	}
}

func matchEntityType(c Condition, entityTypes []string) bool {
	switch c.Operator {
	case "equals":
		val := toString(c.Value)
		for _, et := range entityTypes {
			if strings.EqualFold(et, val) {
				return true
			}
		}
		return false
	case "in":
		vals := toStringSlice(c.Value)
		valSet := make(map[string]bool)
		for _, v := range vals {
			valSet[strings.ToUpper(v)] = true
		}
		for _, et := range entityTypes {
			if valSet[strings.ToUpper(et)] {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func matchString(c Condition, actual string) bool {
	switch c.Operator {
	case "equals":
		return strings.EqualFold(actual, toString(c.Value))
	case "in":
		vals := toStringSlice(c.Value)
		for _, v := range vals {
			if strings.EqualFold(actual, v) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func matchSensitivity(c Condition, actual string) bool {
	order := map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	actualVal := order[strings.ToUpper(actual)]
	targetVal := order[strings.ToUpper(toString(c.Value))]

	switch c.Operator {
	case "equals":
		return actualVal == targetVal
	case "greater_than":
		return actualVal > targetVal
	case "less_than":
		return actualVal < targetVal
	default:
		return false
	}
}

func matchFloat(c Condition, actual float64) bool {
	target := toFloat(c.Value)
	switch c.Operator {
	case "equals":
		return actual == target
	case "greater_than":
		return actual > target
	case "less_than":
		return actual < target
	default:
		return false
	}
}

// ============================================================
// TYPE CONVERSION HELPERS
// ============================================================

func toString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case json.Number:
		return val.String()
	default:
		return ""
	}
}

func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []interface{}:
		result := make([]string, len(val))
		for i, item := range val {
			result[i] = toString(item)
		}
		return result
	case []string:
		return val
	default:
		return nil
	}
}

func toFloat(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case json.Number:
		f, _ := val.Float64()
		return f
	case int:
		return float64(val)
	default:
		return 0
	}
}

// ============================================================
// PARSE RULES FROM DATABASE JSON
// ============================================================

func ParseRulesFromDB(dbRules []struct {
	ID          string
	Name        string
	Priority    int
	Conditions  json.RawMessage
	Action      string
	NotifyAdmin bool
	NotifyUser  bool
}) ([]Rule, error) {
	rules := make([]Rule, len(dbRules))
	for i, dr := range dbRules {
		var conditions []Condition
		if err := json.Unmarshal(dr.Conditions, &conditions); err != nil {
			return nil, err
		}
		rules[i] = Rule{
			ID:          dr.ID,
			Name:        dr.Name,
			Priority:    dr.Priority,
			Conditions:  conditions,
			Action:      dr.Action,
			NotifyAdmin: dr.NotifyAdmin,
			NotifyUser:  dr.NotifyUser,
		}
	}
	return rules, nil
}
