package circuitbreaker_test

// ============================================================
// breaker_test.go — Unit tests for the circuit breaker
//
// Tests cover:
//   - Initial state is CLOSED
//   - CLOSED → OPEN after threshold failures
//   - OPEN rejects calls with ErrCircuitOpen
//   - OPEN → HALF_OPEN after timeout
//   - HALF_OPEN → CLOSED after success threshold
//   - HALF_OPEN → OPEN on single failure
//   - Success in CLOSED resets failure count
//   - Concurrent safety (go test -race)
// ============================================================

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shadow-ai-sentinel/proxy-service/src/circuitbreaker"
)

var errService = errors.New("service error")

func TestBreaker_InitialStateClosed(t *testing.T) {
	cb := circuitbreaker.New(3, 2, time.Second)
	if cb.State() != circuitbreaker.StateClosed {
		t.Errorf("expected CLOSED, got %s", cb.State())
	}
}

func TestBreaker_OpenAfterThresholdFailures(t *testing.T) {
	cb := circuitbreaker.New(3, 2, time.Second)

	for i := 0; i < 3; i++ {
		cb.Execute(func() error { return errService })
	}

	if cb.State() != circuitbreaker.StateOpen {
		t.Errorf("expected OPEN after 3 failures, got %s", cb.State())
	}
}

func TestBreaker_RejectsCallWhenOpen(t *testing.T) {
	cb := circuitbreaker.New(1, 1, time.Hour) // 1 failure → OPEN, long timeout

	cb.Execute(func() error { return errService }) // trip it

	called := false
	err := cb.Execute(func() error {
		called = true
		return nil
	})

	if !errors.Is(err, circuitbreaker.ErrCircuitOpen) {
		t.Errorf("expected ErrCircuitOpen, got %v", err)
	}
	if called {
		t.Error("fn should not be called when circuit is OPEN")
	}
}

func TestBreaker_HalfOpenAfterTimeout(t *testing.T) {
	cb := circuitbreaker.New(1, 1, 10*time.Millisecond)

	cb.Execute(func() error { return errService })
	if cb.State() != circuitbreaker.StateOpen {
		t.Fatalf("expected OPEN, got %s", cb.State())
	}

	time.Sleep(15 * time.Millisecond)

	if cb.State() != circuitbreaker.StateHalfOpen {
		t.Errorf("expected HALF_OPEN after timeout, got %s", cb.State())
	}
}

func TestBreaker_ClosedAfterSuccessThreshold(t *testing.T) {
	cb := circuitbreaker.New(1, 2, 10*time.Millisecond)

	// Trip to OPEN
	cb.Execute(func() error { return errService })
	time.Sleep(15 * time.Millisecond) // → HALF_OPEN

	// Two successes → CLOSED
	cb.Execute(func() error { return nil })
	cb.Execute(func() error { return nil })

	if cb.State() != circuitbreaker.StateClosed {
		t.Errorf("expected CLOSED after 2 successes in HALF_OPEN, got %s", cb.State())
	}
}

func TestBreaker_BackToOpenOnHalfOpenFailure(t *testing.T) {
	cb := circuitbreaker.New(1, 2, 10*time.Millisecond)

	cb.Execute(func() error { return errService }) // → OPEN
	time.Sleep(15 * time.Millisecond)               // → HALF_OPEN

	cb.Execute(func() error { return errService }) // → OPEN again

	if cb.State() != circuitbreaker.StateOpen {
		t.Errorf("expected OPEN after failure in HALF_OPEN, got %s", cb.State())
	}
}

func TestBreaker_SuccessResetFailureCount(t *testing.T) {
	cb := circuitbreaker.New(3, 1, time.Second)

	// 2 failures, then a success should reset the counter
	cb.Execute(func() error { return errService })
	cb.Execute(func() error { return errService })
	cb.Execute(func() error { return nil }) // reset

	// 2 more failures should NOT trip (only 2, need 3 consecutive)
	cb.Execute(func() error { return errService })
	cb.Execute(func() error { return errService })

	if cb.State() != circuitbreaker.StateClosed {
		t.Errorf("expected CLOSED (failures reset after success), got %s", cb.State())
	}
}

func TestBreaker_RecordFailureRecordSuccess(t *testing.T) {
	cb := circuitbreaker.New(2, 1, 10*time.Millisecond)

	cb.RecordFailure()
	cb.RecordFailure()

	if cb.State() != circuitbreaker.StateOpen {
		t.Fatalf("expected OPEN after 2 RecordFailure calls, got %s", cb.State())
	}

	time.Sleep(15 * time.Millisecond) // → HALF_OPEN
	cb.RecordSuccess()

	if cb.State() != circuitbreaker.StateClosed {
		t.Errorf("expected CLOSED after RecordSuccess in HALF_OPEN, got %s", cb.State())
	}
}

func TestBreaker_IsOpen(t *testing.T) {
	cb := circuitbreaker.New(1, 1, time.Hour)

	if cb.IsOpen() {
		t.Error("should not be open initially")
	}

	cb.Execute(func() error { return errService })
	if !cb.IsOpen() {
		t.Error("should be open after failure")
	}
}

func TestBreaker_StateString(t *testing.T) {
	tests := []struct {
		state circuitbreaker.State
		want  string
	}{
		{circuitbreaker.StateClosed, "CLOSED"},
		{circuitbreaker.StateOpen, "OPEN"},
		{circuitbreaker.StateHalfOpen, "HALF_OPEN"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestBreaker_ConcurrentSafety(t *testing.T) {
	cb := circuitbreaker.New(100, 10, 10*time.Millisecond)
	var wg sync.WaitGroup
	const goroutines = 100
	const iterations = 50

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if id%2 == 0 {
					cb.Execute(func() error { return errService })
				} else {
					cb.Execute(func() error { return nil })
				}
				_ = cb.State()
				_ = cb.IsOpen()
			}
		}(g)
	}

	wg.Wait()
	// If we get here without a data race panic, the test passes.
	// The race detector (go test -race) will catch any issues.
}
