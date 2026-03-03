package circuitbreaker

// ============================================================
// Circuit Breaker — 3-state FSM for resilient service calls
//
// States: CLOSED → OPEN → HALF_OPEN → CLOSED
//
// CLOSED:    Normal operation. Failures are counted.
// OPEN:      Fast-fail (ErrCircuitOpen). After halfOpenTimeout, transitions to HALF_OPEN.
// HALF_OPEN: Probe phase. Successes → CLOSED, single failure → OPEN.
//
// Thread-safe via sync.Mutex (not RWMutex because currentState() can mutate state).
// ============================================================

import (
	"errors"
	"sync"
	"time"
)

// ErrCircuitOpen is returned when Execute is called while the breaker is OPEN.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// State represents the circuit breaker state.
type State int

const (
	StateClosed   State = iota // Normal operation
	StateOpen                  // Fast-fail
	StateHalfOpen              // Probing for recovery
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

// CircuitBreaker implements the three-state circuit breaker pattern.
type CircuitBreaker struct {
	mu               sync.Mutex
	state            State
	failures         int
	successes        int
	threshold        int           // consecutive failures to trip OPEN
	successThreshold int           // consecutive successes in HALF_OPEN to close
	halfOpenTimeout  time.Duration // time in OPEN before transitioning to HALF_OPEN
	lastStateChange  time.Time
}

// New creates a CircuitBreaker.
//   - threshold: consecutive failures before opening
//   - successThreshold: consecutive successes in HALF_OPEN before closing
//   - halfOpenTimeout: how long to stay OPEN before probing
func New(threshold, successThreshold int, halfOpenTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:            StateClosed,
		threshold:        threshold,
		successThreshold: successThreshold,
		halfOpenTimeout:  halfOpenTimeout,
		lastStateChange:  time.Now(),
	}
}

// Execute runs fn if the breaker allows it. Returns ErrCircuitOpen if the
// breaker is OPEN. Records success/failure after fn completes.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	cb.mu.Lock()
	st := cb.currentStateLocked()
	if st == StateOpen {
		cb.mu.Unlock()
		return ErrCircuitOpen
	}
	cb.mu.Unlock()

	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()
	if err != nil {
		cb.recordFailureLocked()
	} else {
		cb.recordSuccessLocked()
	}
	return err
}

// RecordFailure records a failure externally (without using Execute).
// Evaluates time-based transitions (OPEN → HALF_OPEN) before recording.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.currentStateLocked() // evaluate time-based transitions first
	cb.recordFailureLocked()
}

// RecordSuccess records a success externally (without using Execute).
// Evaluates time-based transitions (OPEN → HALF_OPEN) before recording.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.currentStateLocked() // evaluate time-based transitions first
	cb.recordSuccessLocked()
}

// IsOpen returns true if the breaker is currently in the OPEN state
// (accounting for halfOpenTimeout transitions).
func (cb *CircuitBreaker) IsOpen() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.currentStateLocked() == StateOpen
}

// State returns the current state (accounting for time-based transitions).
func (cb *CircuitBreaker) State() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.currentStateLocked()
}

// Counts returns current failure and success counts (for testing/debugging).
func (cb *CircuitBreaker) Counts() (failures, successes int) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.failures, cb.successes
}

// currentStateLocked evaluates time-based transitions. Must be called with mu held.
func (cb *CircuitBreaker) currentStateLocked() State {
	if cb.state == StateOpen && time.Since(cb.lastStateChange) >= cb.halfOpenTimeout {
		cb.state = StateHalfOpen
		cb.lastStateChange = time.Now()
		cb.failures = 0
		cb.successes = 0
	}
	return cb.state
}

func (cb *CircuitBreaker) recordFailureLocked() {
	cb.successes = 0
	cb.failures++
	switch cb.state {
	case StateClosed:
		if cb.failures >= cb.threshold {
			cb.state = StateOpen
			cb.lastStateChange = time.Now()
		}
	case StateHalfOpen:
		// Any failure in HALF_OPEN immediately re-opens
		cb.state = StateOpen
		cb.lastStateChange = time.Now()
		cb.failures = 1
	}
}

func (cb *CircuitBreaker) recordSuccessLocked() {
	cb.failures = 0
	cb.successes++
	if cb.state == StateHalfOpen && cb.successes >= cb.successThreshold {
		cb.state = StateClosed
		cb.lastStateChange = time.Now()
		cb.successes = 0
	}
}
