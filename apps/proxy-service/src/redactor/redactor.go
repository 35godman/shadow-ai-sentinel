package redactor

import (
	"fmt"
	"log"
	"sort"
	"strings"
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

// mergeOverlapping removes overlapping detections keeping the one with the
// largest span. Receives detections in any order; returns sorted ascending.
func mergeOverlapping(dets []detection) []detection {
	if len(dets) == 0 {
		return dets
	}
	// Sort ascending by start offset
	sort.Slice(dets, func(i, j int) bool {
		return dets[i].StartOffset < dets[j].StartOffset
	})
	merged := []detection{dets[0]}
	for _, d := range dets[1:] {
		prev := &merged[len(merged)-1]
		if d.StartOffset < prev.EndOffset {
			// Overlap: keep whichever detection ends later (larger span)
			if d.EndOffset > prev.EndOffset {
				*prev = d
			}
		} else {
			merged = append(merged, d)
		}
	}
	return merged
}

// Redact replaces all detected entities with numbered pseudonyms.
// Consistent: same original text always gets the same placeholder within a session.
// Unicode-safe: operates on rune slices so emoji/CJK/Cyrillic offsets are correct.
func Redact(text string, detections []detection) RedactionResult {
	if len(detections) == 0 {
		return RedactionResult{RedactedText: text, Mappings: nil}
	}

	// Merge overlapping detections before redacting to prevent double-replacement corruption.
	merged := mergeOverlapping(detections)

	// Sort by offset descending (replace from end to avoid shifting earlier offsets)
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].StartOffset > merged[j].StartOffset
	})

	// Counter per entity type for consistent naming
	counters := make(map[string]int)
	// Mapping original->placeholder for consistency (same value = same placeholder)
	seen := make(map[string]string)
	var mappings []Mapping

	// Work on rune slice for Unicode-safe offset arithmetic.
	runes := []rune(text)

	for _, d := range merged {
		// Bounds check: skip detections with invalid offsets
		if d.StartOffset < 0 || d.EndOffset > len(runes) || d.StartOffset > d.EndOffset {
			log.Printf("[redactor] skipping out-of-bounds detection: entity=%s start=%d end=%d textRuneLen=%d",
				d.EntityType, d.StartOffset, d.EndOffset, len(runes))
			continue
		}

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

		// Replace rune slice in-place (descending order keeps left-side offsets valid)
		phRunes := []rune(placeholder)
		newRunes := make([]rune, 0, len(runes)-(d.EndOffset-d.StartOffset)+len(phRunes))
		newRunes = append(newRunes, runes[:d.StartOffset]...)
		newRunes = append(newRunes, phRunes...)
		newRunes = append(newRunes, runes[d.EndOffset:]...)
		runes = newRunes
	}

	return RedactionResult{RedactedText: string(runes), Mappings: mappings}
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
// Sorts longest placeholder first to prevent substring collisions
// (e.g., [EMAIL_10] would otherwise be partially matched by [EMAIL_1]).
func ReIdentify(llmResponse string, mappings []Mapping) string {
	if len(mappings) == 0 {
		return llmResponse
	}

	// Sort longest placeholder first to avoid substring collision
	sorted := make([]Mapping, len(mappings))
	copy(sorted, mappings)
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i].Placeholder) > len(sorted[j].Placeholder)
	})

	result := llmResponse
	for _, m := range sorted {
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
