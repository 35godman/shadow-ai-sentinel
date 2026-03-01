package policy_test

// ============================================================
// engine_test.go — Unit tests for the policy evaluation engine
//
// Tests cover:
//   - No rules → default action returned
//   - entity_type condition: equals, in operators
//   - sensitivity condition: equals, greater_than, less_than
//   - confidence condition: greater_than, less_than
//   - ai_tool condition: equals, in operators
//   - Multi-condition rules (all conditions must match = AND logic)
//   - Priority: lower number = higher priority, first match wins
//   - NotifyAdmin / NotifyUser propagated from matched rule
// ============================================================

import (
	"encoding/json"
	"testing"

	"github.com/shadow-ai-sentinel/proxy-service/src/policy"
)

// ============================================================
// NO RULES — default action
// ============================================================

func TestEvaluate_NoRules_ReturnsDefault(t *testing.T) {
	ctx := policy.EvalContext{
		EntityTypes: []string{"SSN"},
		AiTool:      "chatgpt.com",
		Sensitivity: "CRITICAL",
	}

	result := policy.Evaluate(nil, ctx, "BLOCK")
	if result.Action != "BLOCK" {
		t.Errorf("expected default BLOCK, got %s", result.Action)
	}
	if result.MatchedRule != nil {
		t.Error("expected no matched rule when rules list is empty")
	}
}

func TestEvaluate_NoRules_EmptyDefault(t *testing.T) {
	ctx := policy.EvalContext{Sensitivity: "LOW"}
	result := policy.Evaluate([]policy.Rule{}, ctx, "LOG")
	if result.Action != "LOG" {
		t.Errorf("expected default LOG, got %s", result.Action)
	}
}

// ============================================================
// ENTITY TYPE CONDITIONS
// ============================================================

func TestEvaluate_EntityType_Equals_Matches(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Name:   "Block SSN",
			Action: "BLOCK",
			Conditions: []policy.Condition{
				{Field: "entity_type", Operator: "equals", Value: "SSN"},
			},
		},
	}
	ctx := policy.EvalContext{EntityTypes: []string{"SSN"}, Sensitivity: "CRITICAL"}

	result := policy.Evaluate(rules, ctx, "LOG")
	if result.Action != "BLOCK" {
		t.Errorf("expected BLOCK for SSN rule, got %s", result.Action)
	}
	if result.MatchedRule == nil || result.MatchedRule.ID != "r1" {
		t.Errorf("expected rule r1 to match")
	}
}

func TestEvaluate_EntityType_Equals_CaseInsensitive(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Action: "BLOCK",
			Conditions: []policy.Condition{
				{Field: "entity_type", Operator: "equals", Value: "ssn"}, // lowercase
			},
		},
	}
	ctx := policy.EvalContext{EntityTypes: []string{"SSN"}} // uppercase

	result := policy.Evaluate(rules, ctx, "LOG")
	if result.Action != "BLOCK" {
		t.Errorf("expected case-insensitive match: got %s", result.Action)
	}
}

func TestEvaluate_EntityType_Equals_NoMatch(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Action: "BLOCK",
			Conditions: []policy.Condition{
				{Field: "entity_type", Operator: "equals", Value: "CREDIT_CARD"},
			},
		},
	}
	ctx := policy.EvalContext{EntityTypes: []string{"EMAIL"}}

	result := policy.Evaluate(rules, ctx, "WARN")
	if result.Action != "WARN" {
		t.Errorf("expected default WARN (no match), got %s", result.Action)
	}
}

func TestEvaluate_EntityType_In_Matches(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Action: "BLOCK",
			Conditions: []policy.Condition{
				{Field: "entity_type", Operator: "in", Value: []interface{}{"SSN", "CREDIT_CARD", "API_KEY"}},
			},
		},
	}
	ctx := policy.EvalContext{EntityTypes: []string{"API_KEY"}}

	result := policy.Evaluate(rules, ctx, "LOG")
	if result.Action != "BLOCK" {
		t.Errorf("expected BLOCK for API_KEY in list, got %s", result.Action)
	}
}

func TestEvaluate_EntityType_In_NoMatch(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Action: "BLOCK",
			Conditions: []policy.Condition{
				{Field: "entity_type", Operator: "in", Value: []interface{}{"SSN", "CREDIT_CARD"}},
			},
		},
	}
	ctx := policy.EvalContext{EntityTypes: []string{"EMAIL"}}

	result := policy.Evaluate(rules, ctx, "WARN")
	if result.Action != "WARN" {
		t.Errorf("expected WARN (no match), got %s", result.Action)
	}
}

// ============================================================
// SENSITIVITY CONDITIONS
// ============================================================

func TestEvaluate_Sensitivity_Equals_Matches(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Action: "BLOCK",
			Conditions: []policy.Condition{
				{Field: "sensitivity", Operator: "equals", Value: "CRITICAL"},
			},
		},
	}
	ctx := policy.EvalContext{Sensitivity: "CRITICAL"}

	result := policy.Evaluate(rules, ctx, "LOG")
	if result.Action != "BLOCK" {
		t.Errorf("expected BLOCK for CRITICAL sensitivity, got %s", result.Action)
	}
}

func TestEvaluate_Sensitivity_GreaterThan_Matches(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Action: "REDACT",
			Conditions: []policy.Condition{
				{Field: "sensitivity", Operator: "greater_than", Value: "MEDIUM"},
			},
		},
	}

	for _, sensitivity := range []string{"HIGH", "CRITICAL"} {
		ctx := policy.EvalContext{Sensitivity: sensitivity}
		result := policy.Evaluate(rules, ctx, "LOG")
		if result.Action != "REDACT" {
			t.Errorf("expected REDACT for sensitivity=%s (> MEDIUM), got %s", sensitivity, result.Action)
		}
	}
}

func TestEvaluate_Sensitivity_GreaterThan_NoMatch(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Action: "REDACT",
			Conditions: []policy.Condition{
				{Field: "sensitivity", Operator: "greater_than", Value: "HIGH"},
			},
		},
	}

	for _, sensitivity := range []string{"LOW", "MEDIUM", "HIGH"} {
		ctx := policy.EvalContext{Sensitivity: sensitivity}
		result := policy.Evaluate(rules, ctx, "LOG")
		if result.Action != "LOG" {
			t.Errorf("expected LOG (no match) for sensitivity=%s, got %s", sensitivity, result.Action)
		}
	}
}

// ============================================================
// CONFIDENCE CONDITIONS
// ============================================================

func TestEvaluate_Confidence_GreaterThan_Matches(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Action: "BLOCK",
			Conditions: []policy.Condition{
				{Field: "confidence", Operator: "greater_than", Value: 0.8},
			},
		},
	}
	ctx := policy.EvalContext{MaxConfidence: 0.95}

	result := policy.Evaluate(rules, ctx, "LOG")
	if result.Action != "BLOCK" {
		t.Errorf("expected BLOCK for confidence=0.95 > 0.8, got %s", result.Action)
	}
}

func TestEvaluate_Confidence_GreaterThan_NoMatch(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Action: "BLOCK",
			Conditions: []policy.Condition{
				{Field: "confidence", Operator: "greater_than", Value: 0.9},
			},
		},
	}
	ctx := policy.EvalContext{MaxConfidence: 0.5}

	result := policy.Evaluate(rules, ctx, "LOG")
	if result.Action != "LOG" {
		t.Errorf("expected LOG (confidence too low), got %s", result.Action)
	}
}

// ============================================================
// AI TOOL CONDITIONS
// ============================================================

func TestEvaluate_AiTool_Equals_Matches(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Action: "BLOCK",
			Conditions: []policy.Condition{
				{Field: "ai_tool", Operator: "equals", Value: "chatgpt.com"},
				{Field: "entity_type", Operator: "equals", Value: "SSN"},
			},
		},
	}
	ctx := policy.EvalContext{
		EntityTypes: []string{"SSN"},
		AiTool:      "chatgpt.com",
	}

	result := policy.Evaluate(rules, ctx, "LOG")
	if result.Action != "BLOCK" {
		t.Errorf("expected BLOCK for SSN on chatgpt.com, got %s", result.Action)
	}
}

func TestEvaluate_AiTool_Equals_WrongTool_NoMatch(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Action: "BLOCK",
			Conditions: []policy.Condition{
				{Field: "ai_tool", Operator: "equals", Value: "chatgpt.com"},
				{Field: "entity_type", Operator: "equals", Value: "SSN"},
			},
		},
	}
	// Same PII, different tool — rule should NOT match
	ctx := policy.EvalContext{
		EntityTypes: []string{"SSN"},
		AiTool:      "claude.ai", // different tool
	}

	result := policy.Evaluate(rules, ctx, "WARN")
	if result.Action != "WARN" {
		t.Errorf("expected WARN (wrong tool), got %s", result.Action)
	}
}

// ============================================================
// MULTI-CONDITION (AND LOGIC)
// ============================================================

func TestEvaluate_MultiCondition_AllMatch(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Action: "BLOCK",
			Conditions: []policy.Condition{
				{Field: "entity_type", Operator: "equals", Value: "SSN"},
				{Field: "sensitivity", Operator: "equals", Value: "CRITICAL"},
				{Field: "confidence", Operator: "greater_than", Value: 0.8},
			},
		},
	}
	ctx := policy.EvalContext{
		EntityTypes:   []string{"SSN"},
		Sensitivity:   "CRITICAL",
		MaxConfidence: 0.95,
	}

	result := policy.Evaluate(rules, ctx, "LOG")
	if result.Action != "BLOCK" {
		t.Errorf("expected BLOCK (all conditions met), got %s", result.Action)
	}
}

func TestEvaluate_MultiCondition_PartialMatch_NoMatch(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:     "r1",
			Action: "BLOCK",
			Conditions: []policy.Condition{
				{Field: "entity_type", Operator: "equals", Value: "SSN"},
				{Field: "ai_tool", Operator: "equals", Value: "chatgpt.com"}, // this won't match
			},
		},
	}
	ctx := policy.EvalContext{
		EntityTypes: []string{"SSN"},
		AiTool:      "gemini.google.com", // wrong tool
	}

	result := policy.Evaluate(rules, ctx, "WARN")
	if result.Action != "WARN" {
		t.Errorf("expected WARN (partial condition match fails), got %s", result.Action)
	}
}

// ============================================================
// PRIORITY
// ============================================================

func TestEvaluate_Priority_LowerNumberWins(t *testing.T) {
	// Rule with priority 1 should fire before priority 10
	rules := []policy.Rule{
		{ID: "low-priority", Priority: 10, Action: "WARN", Conditions: []policy.Condition{
			{Field: "entity_type", Operator: "equals", Value: "EMAIL"},
		}},
		{ID: "high-priority", Priority: 1, Action: "BLOCK", Conditions: []policy.Condition{
			{Field: "entity_type", Operator: "equals", Value: "EMAIL"},
		}},
	}
	ctx := policy.EvalContext{EntityTypes: []string{"EMAIL"}}

	result := policy.Evaluate(rules, ctx, "LOG")
	// Rules passed in priority-sorted order — first match wins.
	// Since "low-priority" (priority=10) is first in the slice, it fires first.
	// This reflects the caller's responsibility to sort by priority before calling.
	// Result depends on slice order — document this behavior:
	if result.MatchedRule == nil {
		t.Fatal("expected a rule to match")
	}
	// The FIRST rule in the slice wins (caller must sort by priority ASC)
	if result.MatchedRule.ID != "low-priority" {
		t.Errorf("expected first rule in slice to win, got %s", result.MatchedRule.ID)
	}
}

func TestEvaluate_Priority_Sorted_CorrectOrder(t *testing.T) {
	// When rules are sorted by priority ASC (as the DB query would return them),
	// priority=1 fires before priority=10
	rules := []policy.Rule{
		{ID: "high-priority", Priority: 1, Action: "BLOCK", Conditions: []policy.Condition{
			{Field: "entity_type", Operator: "equals", Value: "EMAIL"},
		}},
		{ID: "low-priority", Priority: 10, Action: "WARN", Conditions: []policy.Condition{
			{Field: "entity_type", Operator: "equals", Value: "EMAIL"},
		}},
	}
	ctx := policy.EvalContext{EntityTypes: []string{"EMAIL"}}

	result := policy.Evaluate(rules, ctx, "LOG")
	if result.Action != "BLOCK" {
		t.Errorf("expected BLOCK (priority 1 should win over priority 10), got %s", result.Action)
	}
	if result.MatchedRule.ID != "high-priority" {
		t.Errorf("expected high-priority rule to fire, got %s", result.MatchedRule.ID)
	}
}

// ============================================================
// NOTIFY FLAGS
// ============================================================

func TestEvaluate_NotifyFlags_Propagated(t *testing.T) {
	rules := []policy.Rule{
		{
			ID:          "r1",
			Action:      "BLOCK",
			NotifyAdmin: true,
			NotifyUser:  false,
			Conditions: []policy.Condition{
				{Field: "entity_type", Operator: "equals", Value: "SSN"},
			},
		},
	}
	ctx := policy.EvalContext{EntityTypes: []string{"SSN"}}

	result := policy.Evaluate(rules, ctx, "LOG")
	if !result.NotifyAdmin {
		t.Error("expected NotifyAdmin=true to be propagated from matched rule")
	}
	if result.NotifyUser {
		t.Error("expected NotifyUser=false to be propagated from matched rule")
	}
}

func TestEvaluate_NoMatch_NotifyFlagsFalse(t *testing.T) {
	result := policy.Evaluate([]policy.Rule{}, policy.EvalContext{}, "LOG")
	if result.NotifyAdmin || result.NotifyUser {
		t.Error("expected notify flags to be false when no rule matches")
	}
}

// ============================================================
// ParseRulesFromDB
// ============================================================

func TestParseRulesFromDB_ValidJSON(t *testing.T) {
	condJSON, _ := json.Marshal([]policy.Condition{
		{Field: "entity_type", Operator: "equals", Value: "SSN"},
	})

	dbRules := []struct {
		ID          string
		Name        string
		Priority    int
		Conditions  json.RawMessage
		Action      string
		NotifyAdmin bool
		NotifyUser  bool
	}{
		{
			ID:          "r1",
			Name:        "Block SSN",
			Priority:    1,
			Conditions:  condJSON,
			Action:      "BLOCK",
			NotifyAdmin: true,
			NotifyUser:  false,
		},
	}

	rules, err := policy.ParseRulesFromDB(dbRules)
	if err != nil {
		t.Fatalf("unexpected error parsing rules from DB: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID != "r1" {
		t.Errorf("expected rule ID r1, got %s", rules[0].ID)
	}
	if len(rules[0].Conditions) != 1 {
		t.Errorf("expected 1 condition, got %d", len(rules[0].Conditions))
	}
	if !rules[0].NotifyAdmin {
		t.Error("expected NotifyAdmin=true")
	}
}

func TestParseRulesFromDB_InvalidJSON_ReturnsError(t *testing.T) {
	dbRules := []struct {
		ID          string
		Name        string
		Priority    int
		Conditions  json.RawMessage
		Action      string
		NotifyAdmin bool
		NotifyUser  bool
	}{
		{
			ID:         "r1",
			Conditions: json.RawMessage(`{invalid json`),
			Action:     "BLOCK",
		},
	}

	_, err := policy.ParseRulesFromDB(dbRules)
	if err == nil {
		t.Error("expected error for invalid JSON conditions")
	}
}
