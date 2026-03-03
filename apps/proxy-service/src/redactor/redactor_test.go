package redactor_test

// ============================================================
// redactor_test.go — Unit tests for the redaction engine
//
// Tests cover:
//   - Basic redaction with numbered placeholders
//   - Consistent placeholders for repeated values
//   - Sort-by-offset-descending (correct replacement order)
//   - Re-identification round-trip (redact → LLM → restore)
//   - Hallucinated PII detection
//   - Empty / edge cases
// ============================================================

import (
	"strings"
	"testing"

	"github.com/shadow-ai-sentinel/proxy-service/src/redactor"
)

// ============================================================
// BASIC REDACTION
// ============================================================

func TestRedactFromScanResult_SingleEntity(t *testing.T) {
	text := "My email is john@example.com, please reply soon."
	detections := makeDetections([]detSpec{
		{EntityType: "EMAIL", MatchedText: "john@example.com", Start: 12, End: 28},
	})

	result := redactor.RedactFromScanResult(text, detections)

	if strings.Contains(result.RedactedText, "john@example.com") {
		t.Errorf("original email still present in redacted text: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "[EMAIL_1]") {
		t.Errorf("expected [EMAIL_1] placeholder in redacted text, got: %q", result.RedactedText)
	}
	if len(result.Mappings) != 1 {
		t.Errorf("expected 1 mapping, got %d", len(result.Mappings))
	}
	if result.Mappings[0].Original != "john@example.com" {
		t.Errorf("mapping original should be %q, got %q", "john@example.com", result.Mappings[0].Original)
	}
	if result.Mappings[0].Placeholder != "[EMAIL_1]" {
		t.Errorf("mapping placeholder should be [EMAIL_1], got %q", result.Mappings[0].Placeholder)
	}
}

func TestRedactFromScanResult_MultipleEntities(t *testing.T) {
	text := "SSN: 078-05-1120. Email: bob@test.com."
	detections := makeDetections([]detSpec{
		{EntityType: "SSN", MatchedText: "078-05-1120", Start: 5, End: 16},
		{EntityType: "EMAIL", MatchedText: "bob@test.com", Start: 25, End: 37},
	})

	result := redactor.RedactFromScanResult(text, detections)

	if strings.Contains(result.RedactedText, "078-05-1120") {
		t.Errorf("original SSN still present: %q", result.RedactedText)
	}
	if strings.Contains(result.RedactedText, "bob@test.com") {
		t.Errorf("original email still present: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "[SSN_1]") {
		t.Errorf("expected [SSN_1] in redacted text: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "[EMAIL_1]") {
		t.Errorf("expected [EMAIL_1] in redacted text: %q", result.RedactedText)
	}
	if len(result.Mappings) != 2 {
		t.Errorf("expected 2 mappings, got %d", len(result.Mappings))
	}
}

func TestRedactFromScanResult_NumberedPerEntityType(t *testing.T) {
	// Two different emails should get EMAIL_1 and EMAIL_2
	text := "a@example.com and b@example.com are different people"
	detections := makeDetections([]detSpec{
		{EntityType: "EMAIL", MatchedText: "a@example.com", Start: 0, End: 13},
		{EntityType: "EMAIL", MatchedText: "b@example.com", Start: 18, End: 31},
	})

	result := redactor.RedactFromScanResult(text, detections)

	if !strings.Contains(result.RedactedText, "[EMAIL_1]") {
		t.Errorf("expected [EMAIL_1] in: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "[EMAIL_2]") {
		t.Errorf("expected [EMAIL_2] in: %q", result.RedactedText)
	}
}

func TestRedactFromScanResult_RepeatedValue_SamePlaceholder(t *testing.T) {
	// The same email appearing twice should get the SAME placeholder (consistency)
	text := "user@corp.com called user@corp.com again"
	detections := makeDetections([]detSpec{
		{EntityType: "EMAIL", MatchedText: "user@corp.com", Start: 0, End: 13},
		{EntityType: "EMAIL", MatchedText: "user@corp.com", Start: 21, End: 34},
	})

	result := redactor.RedactFromScanResult(text, detections)

	// Only one unique mapping (same original value)
	if len(result.Mappings) > 1 {
		// The redactor may produce 1 mapping for 2 identical values
		for i, m := range result.Mappings {
			t.Logf("mapping[%d]: %+v", i, m)
		}
	}

	// The redacted text should have the same placeholder in both places
	// Count occurrences of [EMAIL_1] — should appear twice, [EMAIL_2] should not
	count := strings.Count(result.RedactedText, "[EMAIL_1]")
	if count != 2 {
		t.Errorf("expected [EMAIL_1] to appear twice for repeated value, got %d times: %q",
			count, result.RedactedText)
	}
	if strings.Contains(result.RedactedText, "[EMAIL_2]") {
		t.Errorf("unexpected [EMAIL_2] for repeated value: %q", result.RedactedText)
	}
}

// ============================================================
// OFFSET CORRECTNESS (replacements in reverse order)
// ============================================================

func TestRedactFromScanResult_OffsetsCorrect(t *testing.T) {
	// Verify that replacements at the correct positions preserve surrounding text
	text := "hello 078-05-1120 world"
	detections := makeDetections([]detSpec{
		{EntityType: "SSN", MatchedText: "078-05-1120", Start: 6, End: 17},
	})

	result := redactor.RedactFromScanResult(text, detections)

	if !strings.HasPrefix(result.RedactedText, "hello ") {
		t.Errorf("prefix text changed, got: %q", result.RedactedText)
	}
	if !strings.HasSuffix(result.RedactedText, " world") {
		t.Errorf("suffix text changed, got: %q", result.RedactedText)
	}
}

// ============================================================
// RE-IDENTIFICATION
// ============================================================

func TestReIdentify_RestoresOriginalValues(t *testing.T) {
	mappings := []redactor.Mapping{
		{Placeholder: "[EMAIL_1]", Original: "alice@company.com", EntityType: "EMAIL"},
		{Placeholder: "[SSN_1]", Original: "078-05-1120", EntityType: "SSN"},
	}

	llmResponse := "I can see [EMAIL_1] with SSN [SSN_1] in your records."
	restored := redactor.ReIdentify(llmResponse, mappings)

	if strings.Contains(restored, "[EMAIL_1]") {
		t.Errorf("placeholder [EMAIL_1] not replaced in: %q", restored)
	}
	if !strings.Contains(restored, "alice@company.com") {
		t.Errorf("original email not restored in: %q", restored)
	}
	if !strings.Contains(restored, "078-05-1120") {
		t.Errorf("original SSN not restored in: %q", restored)
	}
}

func TestReIdentify_NoMappings_ReturnsUnchanged(t *testing.T) {
	original := "The answer is 42, nothing to restore here."
	result := redactor.ReIdentify(original, nil)

	if result != original {
		t.Errorf("expected unchanged text, got: %q", result)
	}
}

func TestReIdentify_EmptyMappings_ReturnsUnchanged(t *testing.T) {
	original := "Some response text."
	result := redactor.ReIdentify(original, []redactor.Mapping{})

	if result != original {
		t.Errorf("expected unchanged text, got: %q", result)
	}
}

func TestRedactAndReIdentify_RoundTrip(t *testing.T) {
	// Full round-trip: redact → LLM sees placeholders → re-identify → original visible again
	original := "Please process card 4532015112830366 for customer john@example.com"
	detections := makeDetections([]detSpec{
		{EntityType: "CREDIT_CARD", MatchedText: "4532015112830366", Start: 20, End: 36},
		{EntityType: "EMAIL", MatchedText: "john@example.com", Start: 50, End: 66},
	})

	redactResult := redactor.RedactFromScanResult(original, detections)

	// Verify redaction removed originals
	if strings.Contains(redactResult.RedactedText, "4532015112830366") {
		t.Error("card number still present after redaction")
	}
	if strings.Contains(redactResult.RedactedText, "john@example.com") {
		t.Error("email still present after redaction")
	}

	// Simulate LLM responding with the placeholders referenced
	llmResponse := "I'll process the card [CREDIT_CARD_1] for [EMAIL_1]. Done."

	// Re-identify
	restored := redactor.ReIdentify(llmResponse, redactResult.Mappings)

	if strings.Contains(restored, "[CREDIT_CARD_1]") {
		t.Error("placeholder [CREDIT_CARD_1] not replaced after re-identification")
	}
	if !strings.Contains(restored, "4532015112830366") {
		t.Errorf("card number not restored in: %q", restored)
	}
	if !strings.Contains(restored, "john@example.com") {
		t.Errorf("email not restored in: %q", restored)
	}
}

// ============================================================
// HALLUCINATED PII DETECTION
// ============================================================

func TestScanResponseForHallucinatedPII_DetectsLeak(t *testing.T) {
	// The LLM somehow reproduced the original SSN even though we sent [SSN_1]
	mappings := []redactor.Mapping{
		{Placeholder: "[SSN_1]", Original: "078-05-1120", EntityType: "SSN"},
	}

	// LLM hallucinated the original SSN back
	response := "The patient's SSN is 078-05-1120 according to our records."
	leaked := redactor.ScanResponseForHallucinatedPII(response, mappings)

	if len(leaked) == 0 {
		t.Error("expected hallucinated SSN to be detected, but nothing was flagged")
	}
	found := false
	for _, l := range leaked {
		if l == "SSN" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected SSN in leaked types, got: %v", leaked)
	}
}

func TestScanResponseForHallucinatedPII_NoLeak_Clean(t *testing.T) {
	mappings := []redactor.Mapping{
		{Placeholder: "[SSN_1]", Original: "078-05-1120", EntityType: "SSN"},
	}

	// LLM correctly uses the placeholder, original not present
	response := "I processed the SSN record for [SSN_1]."
	leaked := redactor.ScanResponseForHallucinatedPII(response, mappings)

	if len(leaked) != 0 {
		t.Errorf("expected no leakage, but got: %v", leaked)
	}
}

func TestScanResponseForHallucinatedPII_NoMappings_Empty(t *testing.T) {
	leaked := redactor.ScanResponseForHallucinatedPII("some response", nil)
	if len(leaked) != 0 {
		t.Errorf("expected empty result with nil mappings, got: %v", leaked)
	}
}

// ============================================================
// EDGE CASES
// ============================================================

func TestRedactFromScanResult_NoDetections_ReturnsOriginal(t *testing.T) {
	text := "Clean text with no sensitive data."
	result := redactor.RedactFromScanResult(text, makeDetections(nil))

	if result.RedactedText != text {
		t.Errorf("expected original text for empty detections, got: %q", result.RedactedText)
	}
	if len(result.Mappings) != 0 {
		t.Errorf("expected no mappings for empty detections, got %d", len(result.Mappings))
	}
}

func TestRedactFromScanResult_EmptyText(t *testing.T) {
	result := redactor.RedactFromScanResult("", makeDetections(nil))
	if result.RedactedText != "" {
		t.Errorf("expected empty redacted text, got: %q", result.RedactedText)
	}
}

// ============================================================
// HELPERS
// ============================================================

type detSpec struct {
	EntityType  string
	MatchedText string
	Start       int
	End         int
}

// ============================================================
// UNICODE SAFETY TESTS
// ============================================================

func TestRedact_EmojiText_CorrectOffsets(t *testing.T) {
	// "😀 hello john@example.com world"
	// 😀 is 1 rune (4 bytes). Offsets must be rune-based, not byte-based.
	text := "😀 hello john@example.com world"
	runes := []rune(text)
	emailRuneStart := 0
	for i, r := range runes {
		if r == 'j' {
			emailRuneStart = i
			break
		}
	}
	emailRuneEnd := emailRuneStart + len([]rune("john@example.com"))

	detections := makeDetections([]detSpec{
		{EntityType: "EMAIL", MatchedText: "john@example.com", Start: emailRuneStart, End: emailRuneEnd},
	})

	result := redactor.RedactFromScanResult(text, detections)

	if strings.Contains(result.RedactedText, "john@example.com") {
		t.Errorf("original email still present: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "[EMAIL_1]") {
		t.Errorf("expected [EMAIL_1] placeholder, got: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "😀") {
		t.Errorf("emoji was corrupted in: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, " world") {
		t.Errorf("trailing text corrupted in: %q", result.RedactedText)
	}
}

func TestRedact_CyrillicText_CorrectOffsets(t *testing.T) {
	// Cyrillic chars are 2 bytes each — byte vs rune offsets diverge.
	text := "Привет john@example.com мир"
	runes := []rune(text)
	emailRuneStart := 0
	for i, r := range runes {
		if r == 'j' {
			emailRuneStart = i
			break
		}
	}
	emailRuneEnd := emailRuneStart + len([]rune("john@example.com"))

	detections := makeDetections([]detSpec{
		{EntityType: "EMAIL", MatchedText: "john@example.com", Start: emailRuneStart, End: emailRuneEnd},
	})

	result := redactor.RedactFromScanResult(text, detections)

	if strings.Contains(result.RedactedText, "john@example.com") {
		t.Errorf("original email still present: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "Привет") {
		t.Errorf("Cyrillic prefix corrupted: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, " мир") {
		t.Errorf("Cyrillic suffix corrupted: %q", result.RedactedText)
	}
}

// ============================================================
// OVERLAPPING DETECTION MERGE TEST
// ============================================================

func TestRedact_OverlappingDetections_NoCorruption(t *testing.T) {
	// Two detections covering the same span — without merging, double-replacement corrupts text.
	text := "SSN: 078-05-1120 end"
	detections := makeDetections([]detSpec{
		{EntityType: "SSN", MatchedText: "078-05-1120", Start: 5, End: 16},
		{EntityType: "SSN", MatchedText: "078-05-1120", Start: 5, End: 16},
	})

	result := redactor.RedactFromScanResult(text, detections)

	if strings.Contains(result.RedactedText, "078-05-1120") {
		t.Errorf("original SSN still present: %q", result.RedactedText)
	}
	if !strings.HasPrefix(result.RedactedText, "SSN: ") {
		t.Errorf("prefix text corrupted: %q", result.RedactedText)
	}
	if !strings.HasSuffix(result.RedactedText, " end") {
		t.Errorf("suffix text corrupted: %q", result.RedactedText)
	}
}

// ============================================================
// BOUNDS CHECK TEST
// ============================================================

func TestRedact_OutOfBoundsOffset_Skipped(t *testing.T) {
	// A detection with end offset beyond text length must be skipped gracefully.
	text := "Short text"
	detections := makeDetections([]detSpec{
		{EntityType: "EMAIL", MatchedText: "foo@bar.com", Start: 5, End: 9999},
	})

	// Must not panic; should return original text unchanged.
	result := redactor.RedactFromScanResult(text, detections)

	if result.RedactedText != text {
		t.Errorf("expected original text when offset out-of-bounds, got: %q", result.RedactedText)
	}
}

// ============================================================
// RE-IDENTIFICATION LONGEST-FIRST ORDER
// ============================================================

func TestReIdentify_LongestFirst_NoSubstringCollision(t *testing.T) {
	// [EMAIL_1] is a prefix of [EMAIL_10] — wrong order causes partial replacement and garbled output.
	mappings := []redactor.Mapping{
		{Placeholder: "[EMAIL_1]", Original: "alice@example.com", EntityType: "EMAIL"},
		{Placeholder: "[EMAIL_10]", Original: "zebra@example.com", EntityType: "EMAIL"},
	}

	response := "Contact [EMAIL_1] and [EMAIL_10] for the report."
	restored := redactor.ReIdentify(response, mappings)

	if strings.Contains(restored, "[EMAIL_1]") || strings.Contains(restored, "[EMAIL_10]") {
		t.Errorf("placeholders not fully replaced in: %q", restored)
	}
	if !strings.Contains(restored, "alice@example.com") {
		t.Errorf("alice's email not restored in: %q", restored)
	}
	if !strings.Contains(restored, "zebra@example.com") {
		t.Errorf("zebra's email not restored in: %q", restored)
	}
	// Garbled result if [EMAIL_1] replaced before [EMAIL_10]
	if strings.Contains(restored, "alice@example.com0") {
		t.Errorf("substring collision: alice's email got '0' appended: %q", restored)
	}
}

// ============================================================
// OVERLAPPING DETECTIONS — partial, containment, adjacent
// ============================================================

func TestRedact_OverlappingPartial(t *testing.T) {
	// Two detections that partially overlap: [0,10) and [5,15).
	// mergeOverlapping should keep the larger span.
	text := "0123456789ABCDE end"
	detections := makeDetections([]detSpec{
		{EntityType: "SSN", MatchedText: "0123456789", Start: 0, End: 10},
		{EntityType: "SSN", MatchedText: "56789ABCDE", Start: 5, End: 15},
	})

	result := redactor.RedactFromScanResult(text, detections)

	// After merge, only one detection survives (the wider span [0,15) or the later-ending one).
	if strings.Contains(result.RedactedText, "0123456789") {
		t.Errorf("original text still present after partial overlap redaction: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "[SSN_") {
		t.Errorf("expected [SSN_N] placeholder in: %q", result.RedactedText)
	}
	if !strings.HasSuffix(result.RedactedText, " end") {
		t.Errorf("suffix text corrupted after partial overlap: %q", result.RedactedText)
	}
}

func TestRedact_OverlappingFullContainment(t *testing.T) {
	// One detection entirely inside another: [0,10) contains [3,7).
	// mergeOverlapping should keep the outer one.
	text := "ABCDEFGHIJ rest"
	detections := makeDetections([]detSpec{
		{EntityType: "EMAIL", MatchedText: "ABCDEFGHIJ", Start: 0, End: 10},
		{EntityType: "EMAIL", MatchedText: "DEFG", Start: 3, End: 7},
	})

	result := redactor.RedactFromScanResult(text, detections)

	if strings.Contains(result.RedactedText, "ABCDEFGHIJ") {
		t.Errorf("original text still present: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "[EMAIL_1]") {
		t.Errorf("expected [EMAIL_1] placeholder in: %q", result.RedactedText)
	}
	if !strings.HasSuffix(result.RedactedText, " rest") {
		t.Errorf("suffix corrupted: %q", result.RedactedText)
	}
}

func TestRedact_AdjacentDetections(t *testing.T) {
	// Two detections back-to-back with zero gap: [0,5) and [5,10).
	text := "AAAAABBBBB end"
	detections := makeDetections([]detSpec{
		{EntityType: "SSN", MatchedText: "AAAAA", Start: 0, End: 5},
		{EntityType: "EMAIL", MatchedText: "BBBBB", Start: 5, End: 10},
	})

	result := redactor.RedactFromScanResult(text, detections)

	if strings.Contains(result.RedactedText, "AAAAA") {
		t.Errorf("first entity still present: %q", result.RedactedText)
	}
	if strings.Contains(result.RedactedText, "BBBBB") {
		t.Errorf("second entity still present: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "[SSN_1]") {
		t.Errorf("expected [SSN_1] in: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "[EMAIL_1]") {
		t.Errorf("expected [EMAIL_1] in: %q", result.RedactedText)
	}
}

// ============================================================
// MULTIBYTE CHARACTER TESTS — CJK, emoji, mixed scripts
// ============================================================

func TestRedact_MultibyteCJK(t *testing.T) {
	// CJK characters (3 bytes each, 1 rune each).
	// "你好 secret@email.com 世界"
	text := "你好 secret@email.com 世界"
	runes := []rune(text)
	// Find "secret@email.com" rune positions.
	emailStr := "secret@email.com"
	emailStart := -1
	for i := range runes {
		if string(runes[i:i+len([]rune(emailStr))]) == emailStr {
			emailStart = i
			break
		}
	}
	if emailStart == -1 {
		t.Fatal("could not find email in CJK text")
	}
	emailEnd := emailStart + len([]rune(emailStr))

	detections := makeDetections([]detSpec{
		{EntityType: "EMAIL", MatchedText: emailStr, Start: emailStart, End: emailEnd},
	})

	result := redactor.RedactFromScanResult(text, detections)

	if strings.Contains(result.RedactedText, "secret@email.com") {
		t.Errorf("email still present: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "你好") {
		t.Errorf("CJK prefix corrupted: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "世界") {
		t.Errorf("CJK suffix corrupted: %q", result.RedactedText)
	}
	if !strings.Contains(result.RedactedText, "[EMAIL_1]") {
		t.Errorf("expected [EMAIL_1] placeholder: %q", result.RedactedText)
	}
}

func TestRedact_MultibyteEmoji_KeySymbol(t *testing.T) {
	// Emoji 🔑 = 1 rune, 4 bytes. Ensure rune offsets work correctly.
	text := "🔑 key: sk-abc123def456 🔑"
	runes := []rune(text)
	// "sk-abc123def456" starts at rune 7
	keyStr := "sk-abc123def456"
	keyStart := -1
	for i := range runes {
		if i+len([]rune(keyStr)) <= len(runes) && string(runes[i:i+len([]rune(keyStr))]) == keyStr {
			keyStart = i
			break
		}
	}
	if keyStart == -1 {
		t.Fatal("could not find key in emoji text")
	}
	keyEnd := keyStart + len([]rune(keyStr))

	detections := makeDetections([]detSpec{
		{EntityType: "API_KEY", MatchedText: keyStr, Start: keyStart, End: keyEnd},
	})

	result := redactor.RedactFromScanResult(text, detections)

	if strings.Contains(result.RedactedText, "sk-abc123def456") {
		t.Errorf("key still present: %q", result.RedactedText)
	}
	// Both emoji should survive
	if strings.Count(result.RedactedText, "🔑") != 2 {
		t.Errorf("emoji corrupted, expected 2 🔑, got: %q", result.RedactedText)
	}
}

// ============================================================
// LONG TEXT PERFORMANCE TEST
// ============================================================

func TestRedact_LongText_100KB(t *testing.T) {
	// 100KB text with detections scattered throughout.
	// Verify correctness and that it doesn't hang.
	size := 100 * 1024
	buf := make([]rune, size)
	for i := range buf {
		buf[i] = 'A' + rune(i%26)
	}
	text := string(buf)

	// Place 15 detections at regular intervals.
	var specs []detSpec
	step := size / 16
	for i := 0; i < 15; i++ {
		start := step * (i + 1)
		end := start + 5
		if end > size {
			break
		}
		specs = append(specs, detSpec{
			EntityType:  "SSN",
			MatchedText: string(buf[start : start+5]),
			Start:       start,
			End:         end,
		})
	}

	detections := makeDetections(specs)
	result := redactor.RedactFromScanResult(text, detections)

	// Verify all detections were redacted.
	ssnCount := strings.Count(result.RedactedText, "[SSN_")
	if ssnCount != 15 {
		t.Errorf("expected 15 [SSN_N] placeholders in 100KB text, got %d", ssnCount)
	}
}

// ============================================================
// EDGE CASES: start/end boundaries
// ============================================================

func TestRedact_SingleDetectionAtStart(t *testing.T) {
	text := "SENSITIVE rest of text"
	detections := makeDetections([]detSpec{
		{EntityType: "SSN", MatchedText: "SENSITIVE", Start: 0, End: 9},
	})

	result := redactor.RedactFromScanResult(text, detections)

	if !strings.HasPrefix(result.RedactedText, "[SSN_1]") {
		t.Errorf("expected redaction at start, got: %q", result.RedactedText)
	}
	if !strings.HasSuffix(result.RedactedText, " rest of text") {
		t.Errorf("suffix corrupted: %q", result.RedactedText)
	}
}

func TestRedact_SingleDetectionAtEnd(t *testing.T) {
	text := "prefix SENSITIVE"
	detections := makeDetections([]detSpec{
		{EntityType: "EMAIL", MatchedText: "SENSITIVE", Start: 7, End: 16},
	})

	result := redactor.RedactFromScanResult(text, detections)

	if !strings.HasPrefix(result.RedactedText, "prefix ") {
		t.Errorf("prefix corrupted: %q", result.RedactedText)
	}
	if !strings.HasSuffix(result.RedactedText, "[EMAIL_1]") {
		t.Errorf("expected redaction at end, got: %q", result.RedactedText)
	}
}

// makeDetections converts test specs to the anonymous struct type required by RedactFromScanResult.
func makeDetections(specs []detSpec) []struct {
	EntityType  string
	MatchedText string
	StartOffset int
	EndOffset   int
} {
	if specs == nil {
		return []struct {
			EntityType  string
			MatchedText string
			StartOffset int
			EndOffset   int
		}{}
	}
	out := make([]struct {
		EntityType  string
		MatchedText string
		StartOffset int
		EndOffset   int
	}, len(specs))
	for i, s := range specs {
		out[i].EntityType = s.EntityType
		out[i].MatchedText = s.MatchedText
		out[i].StartOffset = s.Start
		out[i].EndOffset = s.End
	}
	return out
}
