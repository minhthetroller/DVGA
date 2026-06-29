package main

import (
	"sync"
)

// Stage of an in-flight Fargate launch.
type Stage string

const (
	StageSubmitting   Stage = "submitting"
	StageProvisioning Stage = "provisioning"
	StageStarting     Stage = "starting"
	StageRouting      Stage = "routing"
	StageReady        Stage = "ready"
	StageFailed       Stage = "failed"
)

// LaunchState is the progress snapshot for one user's launch, returned
// to the browser via GET /launch/{username}.
type LaunchState struct {
	Stage   Stage  `json:"stage"`
	Percent int    `json:"percent"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// LaunchTracker holds the in-flight launch states keyed by username.
// It is safe for concurrent use.
type LaunchTracker struct {
	mu     sync.RWMutex
	states map[string]LaunchState
}

func NewLaunchTracker() *LaunchTracker {
	return &LaunchTracker{states: make(map[string]LaunchState)}
}

func (t *LaunchTracker) Set(username string, state LaunchState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.states[username] = state
}

func (t *LaunchTracker) Get(username string) (LaunchState, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s, ok := t.states[username]
	return s, ok
}

func (t *LaunchTracker) Delete(username string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.states, username)
}
