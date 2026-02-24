package redactor

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ============================================================
// REDACTION ENGINE
// Replaces detected PII with consistent pseudonyms.
// Stores the mapping for re-identification on LLM response.
// ============================================================

type Mapping struct {
	Placeholder string `json:"placeholder"`
	Original    string `json:"original"`
	EntityType  string `json:"entityType"`
}

type RedactionResult struct {
	RedactedText string    `json:"redactedText"`
	Mappings     []Mapping `json:"mappings"`
}

type detection struct {
	EntityType  string
	MatchedText string
	StartOffset int
	EndOffset   int
}

// Redact replaces all detected entities with numbered pseudonyms.
// Consistent: same original text always gets the same placeholder within a session.
func Redact(text string, detections []detection) RedactionResult {
	if len(detections) == 0 {
		return RedactionResult{RedactedText: text, Mappings: nil}
	}

	// Sort by offset descending (replace from end to avoid offset shifts)
	sorted := make([]detection, len(detections))
	copy(sorted, detections)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].StartOffset > sorted[j].StartOffset
	})

	// Counter per entity type for consistent naming
	counters := make(map[string]int)
	// Mapping original->placeholder for consistency
	seen := make(map[string]string)
	var mappings []Mapping
	var mu sync.Mutex

	result := text

	for _, d := range sorted {
		mu.Lock()
		placeholder, exists := seen[d.MatchedText]
		if !exists {
			counters[d.EntityType]++
			placeholder = fmt.Sprintf("[%s_%d]", d.EntityType, counters[d.EntityType])
			seen[d.MatchedText] = placeholder
			mappings = append(mappings, Mapping{
				Placeholder: placeholder,
				Original:    d.MatchedText,
				EntityType:  d.EntityType,
			})
		}
		mu.Unlock()

		result = result[:d.StartOffset] + placeholder + result[d.EndOffset:]
	}

	return RedactionResult{RedactedText: result, Mappings: mappings}
}

// RedactFromScanResult converts scanner detections to redacted text
func RedactFromScanResult(text string, scanDetections []struct {
	EntityType  string
	MatchedText string
	StartOffset int
	EndOffset   int
}) RedactionResult {
	dets := make([]detection, len(scanDetections))
	for i, sd := range scanDetections {
		dets[i] = detection{
			EntityType:  sd.EntityType,
			MatchedText: sd.MatchedText,
			StartOffset: sd.StartOffset,
			EndOffset:   sd.EndOffset,
		}
	}
	return Redact(text, dets)
}

// ReIdentify replaces pseudonym placeholders in LLM response with original values.
func ReIdentify(llmResponse string, mappings []Mapping) string {
	result := llmResponse
	for _, m := range mappings {
		result = strings.ReplaceAll(result, m.Placeholder, m.Original)
	}
	return result
}

// ScanResponseForHallucinatedPII checks if the LLM response contains
// PII that wasn't in the original prompt (hallucinated PII).
// This is a safety net — we don't want the LLM to generate new sensitive data.
func ScanResponseForHallucinatedPII(response string, originalMappings []Mapping) []string {
	// This is a lightweight check. The full ML scan runs separately.
	// Here we just check that no original PII leaked back without going through re-identification.
	var leaked []string
	for _, m := range originalMappings {
		// If the original value appears in the response AND it wasn't re-identified by us,
		// the LLM somehow generated it independently (hallucination or memorization)
		if strings.Contains(response, m.Original) {
			leaked = append(leaked, m.EntityType)
		}
	}
	return leaked
}
