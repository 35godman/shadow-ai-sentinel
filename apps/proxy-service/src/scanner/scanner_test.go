package scanner_test

// ============================================================
// scanner_test.go — Unit tests for the regex scanning engine
//
// Tests cover:
//   - True positives: real PII/secrets that MUST be detected
//   - True negatives: clean text that must NOT trigger detection
//   - Validator logic: Luhn, SSN area/group/serial rules, entropy
//   - Risk scoring and action determination
//   - Enabled-type filtering
// ============================================================

import (
	"strings"
	"testing"

	"github.com/shadow-ai-sentinel/proxy-service/src/scanner"
)

// ============================================================
// SSN TESTS
// ============================================================

func TestSSN_ValidDashed_Detected(t *testing.T) {
	result := scanner.ScanText("Please verify my SSN: 078-05-1120", nil)

	assertHasEntityType(t, result.Detections, "SSN")
	assertAction(t, result, "BLOCK")
	assertRisk(t, result, "CRITICAL")
}

func TestSSN_InSentence_Detected(t *testing.T) {
	result := scanner.ScanText("Patient ID 421-33-7890 admitted on Monday", nil)

	assertHasEntityType(t, result.Detections, "SSN")
}

func TestSSN_InvalidAreaZero_NotDetected(t *testing.T) {
	// Area 000 is invalid
	result := scanner.ScanText("number: 000-12-3456", nil)

	assertNoEntityType(t, result.Detections, "SSN")
}

func TestSSN_InvalidArea666_NotDetected(t *testing.T) {
	result := scanner.ScanText("number: 666-12-3456", nil)

	assertNoEntityType(t, result.Detections, "SSN")
}

func TestSSN_InvalidGroupZero_NotDetected(t *testing.T) {
	result := scanner.ScanText("number: 123-00-4567", nil)

	assertNoEntityType(t, result.Detections, "SSN")
}

func TestSSN_InvalidSerialZero_NotDetected(t *testing.T) {
	result := scanner.ScanText("number: 123-45-0000", nil)

	assertNoEntityType(t, result.Detections, "SSN")
}

func TestSSN_KnownTestValue_NotDetected(t *testing.T) {
	result := scanner.ScanText("example: 123-45-6789", nil)

	assertNoEntityType(t, result.Detections, "SSN")
}

func TestSSN_RandomDate_NotFalsePositive(t *testing.T) {
	// Phone or date-like numbers should not match SSN pattern (dashed format different)
	result := scanner.ScanText("date: 2024-01-15", nil)

	assertNoEntityType(t, result.Detections, "SSN")
}

// ============================================================
// CREDIT CARD TESTS
// ============================================================

func TestCreditCard_Visa_Valid_Detected(t *testing.T) {
	// 4532015112830366 is a valid Visa test number (passes Luhn)
	result := scanner.ScanText("Card: 4532015112830366", nil)

	assertHasEntityType(t, result.Detections, "CREDIT_CARD")
	assertAction(t, result, "BLOCK")
}

func TestCreditCard_Visa_WithSpaces_Detected(t *testing.T) {
	result := scanner.ScanText("Card: 4532 0151 1283 0366", nil)

	assertHasEntityType(t, result.Detections, "CREDIT_CARD")
}

func TestCreditCard_Mastercard_Valid_Detected(t *testing.T) {
	// 5425233430109903 is a valid Mastercard test number
	result := scanner.ScanText("MC: 5425233430109903", nil)

	assertHasEntityType(t, result.Detections, "CREDIT_CARD")
}

func TestCreditCard_InvalidLuhn_NotDetected(t *testing.T) {
	// Starts with 4 (looks like Visa) but fails Luhn
	result := scanner.ScanText("Card: 4532015112830367", nil)

	assertNoEntityType(t, result.Detections, "CREDIT_CARD")
}

func TestCreditCard_Random16Digits_NotDetected(t *testing.T) {
	// 16 digits not starting with 4, 5, 3 should not match Visa/MC/Amex
	result := scanner.ScanText("id: 9999999999999999", nil)

	assertNoEntityType(t, result.Detections, "CREDIT_CARD")
}

// ============================================================
// API KEY TESTS
// ============================================================

func TestAPIKey_OpenAI_Detected(t *testing.T) {
	// Realistic-looking OpenAI key (high entropy, correct prefix)
	result := scanner.ScanText("key = sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd", nil)

	assertHasEntityType(t, result.Detections, "API_KEY")
	assertAction(t, result, "BLOCK")
}

func TestAPIKey_Anthropic_Detected(t *testing.T) {
	result := scanner.ScanText("ANTHROPIC_KEY=sk-ant-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcd", nil)

	assertHasEntityType(t, result.Detections, "API_KEY")
}

func TestAPIKey_GitHub_Detected(t *testing.T) {
	result := scanner.ScanText("token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abc", nil)

	assertHasEntityType(t, result.Detections, "API_KEY")
}

func TestAPIKey_AWS_Detected(t *testing.T) {
	result := scanner.ScanText("Access Key: AKIAIOSFODNN7EXAMPLE", nil)

	assertHasEntityType(t, result.Detections, "AWS_KEY")
}

func TestAPIKey_Stripe_Live_Detected(t *testing.T) {
	// Constructed at runtime to avoid triggering static secret scanners.
	// This is a fake test value — not a real key.
	fakeStripeKey := "STRIPE_SECRET=" + "sk_" + "live_aBcDeFgHiJkLmNoPqRsTuVwXy"
	result := scanner.ScanText(fakeStripeKey, nil)

	assertHasEntityType(t, result.Detections, "API_KEY")
}

func TestAPIKey_LowEntropy_NotDetected(t *testing.T) {
	// sk- prefix but low entropy (all same char) should fail validator
	result := scanner.ScanText("key = sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)

	// Low entropy, should not be detected as API_KEY
	for _, d := range result.Detections {
		if d.EntityType == "API_KEY" && strings.Contains(d.MatchedText, "sk-aaa") {
			t.Errorf("low-entropy sk- string was incorrectly flagged as API_KEY: %s", d.MatchedText)
		}
	}
}

// ============================================================
// CREDENTIALS TESTS
// ============================================================

func TestCredentials_DBConnectionString_Detected(t *testing.T) {
	result := scanner.ScanText("DATABASE_URL=postgres://user:pass@localhost:5432/mydb", nil)

	assertHasEntityType(t, result.Detections, "CREDENTIALS")
	assertAction(t, result, "BLOCK")
}

func TestCredentials_PrivateKey_Detected(t *testing.T) {
	result := scanner.ScanText("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...", nil)

	assertHasEntityType(t, result.Detections, "CREDENTIALS")
}

func TestCredentials_MongoDB_Detected(t *testing.T) {
	result := scanner.ScanText("uri = mongodb://admin:secret@cluster.example.com:27017/db", nil)

	assertHasEntityType(t, result.Detections, "CREDENTIALS")
}

// ============================================================
// EMAIL TESTS
// ============================================================

func TestEmail_Standard_Detected(t *testing.T) {
	result := scanner.ScanText("Contact john.doe@example.com for details", nil)

	assertHasEntityType(t, result.Detections, "EMAIL")
	assertAction(t, result, "WARN")
}

func TestEmail_Subdomain_Detected(t *testing.T) {
	result := scanner.ScanText("Email: admin@mail.company.org", nil)

	assertHasEntityType(t, result.Detections, "EMAIL")
}

func TestEmail_Multiple_DetectedAll(t *testing.T) {
	result := scanner.ScanText("Send to alice@example.com and bob@company.io", nil)

	count := countEntityType(result.Detections, "EMAIL")
	if count < 2 {
		t.Errorf("expected at least 2 email detections, got %d", count)
	}
}

// ============================================================
// PHONE TESTS
// ============================================================

func TestPhone_USFormat_Detected(t *testing.T) {
	result := scanner.ScanText("Call me at (555) 867-5309", nil)

	assertHasEntityType(t, result.Detections, "PHONE")
}

func TestPhone_DashedFormat_Detected(t *testing.T) {
	result := scanner.ScanText("Phone: 555-867-5309", nil)

	assertHasEntityType(t, result.Detections, "PHONE")
}

// ============================================================
// GCP KEY TESTS
// ============================================================

func TestGCPKey_ServiceAccount_Detected(t *testing.T) {
	text := `{"type": "service_account", "private_key": "-----BEGIN RSA PRIVATE KEY-----\nXXX"}`
	result := scanner.ScanText(text, nil)

	assertHasEntityType(t, result.Detections, "GCP_KEY")
}

// ============================================================
// COMBINED RISK AND ACTION TESTS
// ============================================================

func TestRisk_NoDetections_LowAndLog(t *testing.T) {
	result := scanner.ScanText("Hello, how can I help you today?", nil)

	if result.CombinedRisk != "LOW" {
		t.Errorf("expected LOW risk for clean text, got %s", result.CombinedRisk)
	}
	if result.RecommendedAction != "LOG" {
		t.Errorf("expected LOG action for clean text, got %s", result.RecommendedAction)
	}
	if len(result.Detections) != 0 {
		t.Errorf("expected 0 detections for clean text, got %d", len(result.Detections))
	}
}

func TestRisk_EmailOnly_MediumAndWarn(t *testing.T) {
	result := scanner.ScanText("Email: test@example.com", nil)

	if result.CombinedRisk != "MEDIUM" {
		t.Errorf("expected MEDIUM risk for email, got %s", result.CombinedRisk)
	}
	if result.RecommendedAction != "WARN" {
		t.Errorf("expected WARN action for email, got %s", result.RecommendedAction)
	}
}

func TestRisk_GitHubToken_HighAndRedact(t *testing.T) {
	result := scanner.ScanText("token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abc", nil)

	if result.CombinedRisk != "HIGH" {
		t.Errorf("expected HIGH risk for GitHub token, got %s", result.CombinedRisk)
	}
	if result.RecommendedAction != "REDACT" {
		t.Errorf("expected REDACT action for GitHub token, got %s", result.RecommendedAction)
	}
}

func TestRisk_SSN_CriticalAndBlock(t *testing.T) {
	result := scanner.ScanText("SSN: 078-05-1120", nil)

	if result.CombinedRisk != "CRITICAL" {
		t.Errorf("expected CRITICAL risk for SSN, got %s", result.CombinedRisk)
	}
	if result.RecommendedAction != "BLOCK" {
		t.Errorf("expected BLOCK action for SSN, got %s", result.RecommendedAction)
	}
}

func TestRisk_MixedContent_HighestWins(t *testing.T) {
	// SSN (CRITICAL) + email (MEDIUM) → CRITICAL wins
	result := scanner.ScanText("Contact john@example.com, SSN: 078-05-1120", nil)

	if result.CombinedRisk != "CRITICAL" {
		t.Errorf("expected CRITICAL (SSN beats email), got %s", result.CombinedRisk)
	}
	if result.RecommendedAction != "BLOCK" {
		t.Errorf("expected BLOCK, got %s", result.RecommendedAction)
	}
}

// ============================================================
// ENABLED TYPES FILTER
// ============================================================

func TestEnabledTypes_OnlyEmail_SkipsSSN(t *testing.T) {
	// Only enable EMAIL detector — SSN should be skipped
	result := scanner.ScanText("SSN: 078-05-1120, email: test@example.com", []string{"EMAIL"})

	assertNoEntityType(t, result.Detections, "SSN")
	assertHasEntityType(t, result.Detections, "EMAIL")
}

func TestEnabledTypes_Empty_ScansAll(t *testing.T) {
	result := scanner.ScanText("SSN: 078-05-1120", nil)

	assertHasEntityType(t, result.Detections, "SSN")
}

// ============================================================
// DETECTION METADATA
// ============================================================

func TestDetection_HasOffsets(t *testing.T) {
	text := "My SSN is 078-05-1120 ok"
	result := scanner.ScanText(text, nil)

	var ssnDetection *scanner.Detection
	for i := range result.Detections {
		if result.Detections[i].EntityType == "SSN" {
			ssnDetection = &result.Detections[i]
			break
		}
	}
	if ssnDetection == nil {
		t.Fatal("SSN detection not found")
	}
	if ssnDetection.StartOffset < 0 || ssnDetection.EndOffset <= ssnDetection.StartOffset {
		t.Errorf("invalid offsets: start=%d end=%d", ssnDetection.StartOffset, ssnDetection.EndOffset)
	}
	// Verify the matched text is actually at those offsets
	matched := text[ssnDetection.StartOffset:ssnDetection.EndOffset]
	if !strings.Contains(matched, "078-05-1120") {
		t.Errorf("offset range does not contain SSN: %q", matched)
	}
}

func TestDetection_HasConfidence(t *testing.T) {
	result := scanner.ScanText("SSN: 078-05-1120", nil)

	for _, d := range result.Detections {
		if d.EntityType == "SSN" && d.Confidence <= 0 {
			t.Errorf("expected confidence > 0, got %f", d.Confidence)
		}
	}
}

func TestDetection_HasRedactedText(t *testing.T) {
	result := scanner.ScanText("SSN: 078-05-1120", nil)

	for _, d := range result.Detections {
		if d.EntityType == "SSN" {
			if d.RedactedText == "" {
				t.Error("expected non-empty RedactedText")
			}
			if !strings.Contains(d.RedactedText, "SSN") {
				t.Errorf("expected RedactedText to reference entity type, got %q", d.RedactedText)
			}
		}
	}
}

func TestScanDurationRecorded(t *testing.T) {
	result := scanner.ScanText("test content", nil)
	if result.ScanDurationMs < 0 {
		t.Errorf("expected non-negative scan duration, got %f", result.ScanDurationMs)
	}
}

// ============================================================
// VALIDATOR UNIT TESTS
// ============================================================

func TestLuhnCheck(t *testing.T) {
	cases := []struct {
		number string
		valid  bool
	}{
		{"4532015112830366", true},  // Valid Visa
		{"5425233430109903", true},  // Valid Mastercard
		{"4532015112830367", false}, // Invalid (last digit off)
		{"1234567890123456", false}, // Random 16 digits
		{"0000000000000000", false}, // All zeros
	}

	for _, tc := range cases {
		t.Run(tc.number, func(t *testing.T) {
			result := scanner.ScanText("card: "+tc.number, []string{"CREDIT_CARD"})
			found := countEntityType(result.Detections, "CREDIT_CARD") > 0
			if found != tc.valid {
				t.Errorf("Luhn(%s): expected valid=%v, got found=%v", tc.number, tc.valid, found)
			}
		})
	}
}

// ============================================================
// HELPERS
// ============================================================

func assertHasEntityType(t *testing.T, detections []scanner.Detection, entityType string) {
	t.Helper()
	for _, d := range detections {
		if d.EntityType == entityType {
			return
		}
	}
	t.Errorf("expected detection of type %q but not found in %v", entityType, summarizeDetections(detections))
}

func assertNoEntityType(t *testing.T, detections []scanner.Detection, entityType string) {
	t.Helper()
	for _, d := range detections {
		if d.EntityType == entityType {
			t.Errorf("unexpected detection of type %q (matched: %q)", entityType, d.MatchedText)
			return
		}
	}
}

func assertAction(t *testing.T, result scanner.ScanResult, expected string) {
	t.Helper()
	if result.RecommendedAction != expected {
		t.Errorf("expected action %q, got %q (risk=%s)", expected, result.RecommendedAction, result.CombinedRisk)
	}
}

func assertRisk(t *testing.T, result scanner.ScanResult, expected string) {
	t.Helper()
	if result.CombinedRisk != expected {
		t.Errorf("expected risk %q, got %q", expected, result.CombinedRisk)
	}
}

func countEntityType(detections []scanner.Detection, entityType string) int {
	count := 0
	for _, d := range detections {
		if d.EntityType == entityType {
			count++
		}
	}
	return count
}

func summarizeDetections(detections []scanner.Detection) []string {
	var out []string
	for _, d := range detections {
		out = append(out, d.EntityType+":"+d.MatchedText)
	}
	return out
}
