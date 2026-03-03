package scanner

// ============================================================
// Deterministic Timeout Budget
//
// Allocates a fixed time budget per scan request, divided into:
//   - Regex phase:  fast, hard-capped (default 100ms)
//   - ML phase:     bounded by remaining budget (default up to 3s)
//
// If the ML allocation is exhausted or the circuit breaker is open,
// the Degraded flag signals that results are regex-only.
// ============================================================

import (
	"context"
	"time"
)

const (
	DefaultTotalBudget = 10 * time.Second
	DefaultRegexAlloc  = 100 * time.Millisecond
	DefaultMLAlloc     = 3 * time.Second
)

// Budget tracks time allocation for a single scan request.
// Created per-request — not shared across goroutines, no synchronization needed.
type Budget struct {
	start      time.Time
	total      time.Duration
	regexAlloc time.Duration
	mlAlloc    time.Duration
	mlDegraded bool
}

// NewBudget creates a budget with the given allocations.
func NewBudget(total, regexAlloc, mlAlloc time.Duration) *Budget {
	return &Budget{
		start:      time.Now(),
		total:      total,
		regexAlloc: regexAlloc,
		mlAlloc:    mlAlloc,
	}
}

// DefaultBudget creates a budget with the default allocations.
func DefaultBudget() *Budget {
	return NewBudget(DefaultTotalBudget, DefaultRegexAlloc, DefaultMLAlloc)
}

// RegexContext returns a context bounded by the regex time allocation.
// The returned context is a child of parent with a deadline of min(regexAlloc, remaining).
func (b *Budget) RegexContext(parent context.Context) (context.Context, context.CancelFunc) {
	rem := b.Remaining()
	alloc := b.regexAlloc
	if alloc > rem {
		alloc = rem
	}
	if alloc <= 0 {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, cancel
	}
	return context.WithTimeout(parent, alloc)
}

// MLContext returns a context bounded by the ML time allocation.
// If no budget remains, the context is immediately cancelled and Degraded is set.
func (b *Budget) MLContext(parent context.Context) (context.Context, context.CancelFunc) {
	rem := b.Remaining()
	if rem <= 0 {
		b.mlDegraded = true
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, cancel
	}
	alloc := b.mlAlloc
	if alloc > rem {
		alloc = rem
	}
	return context.WithTimeout(parent, alloc)
}

// Remaining returns the time left in the total budget.
func (b *Budget) Remaining() time.Duration {
	return b.total - time.Since(b.start)
}

// Elapsed returns how much time has been used so far.
func (b *Budget) Elapsed() time.Duration {
	return time.Since(b.start)
}

// Degraded returns true if the ML phase was skipped due to budget exhaustion
// or an external call to MarkMLDegraded.
func (b *Budget) Degraded() bool {
	return b.mlDegraded
}

// MarkMLDegraded sets the degraded flag (e.g. circuit breaker open, ML error).
func (b *Budget) MarkMLDegraded() {
	b.mlDegraded = true
}
