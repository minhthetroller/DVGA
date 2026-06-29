// Package session manages per-user HTTP session state.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// Session represents an authenticated user session.
type Session struct {
	UserID    int
	Username  string
	Role      string
	CreatedAt time.Time
}

// AttemptTracker tracks rate-limiting state for a key (username or IP).
type AttemptTracker struct {
	Count     int
	LastFail  time.Time
	LockUntil time.Time
}

// Manager is an in-memory session store with rate-limiting support.
type Manager struct {
	mu            sync.RWMutex
	sessions      map[string]*Session
	loginAttempts map[string]*AttemptTracker
	resetAttempts map[string]*AttemptTracker
	stopCh        chan struct{}
	secret        []byte
}

func NewManager() *Manager {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic("session: failed to generate HMAC secret: " + err.Error())
	}
	return &Manager{
		sessions:      make(map[string]*Session),
		loginAttempts: make(map[string]*AttemptTracker),
		resetAttempts: make(map[string]*AttemptTracker),
		secret:        secret,
	}
}

// Create stores a new session and returns the token.
func (m *Manager) Create(userID int, username, role string) string {
	token := generateToken()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[token] = &Session{
		UserID:    userID,
		Username:  username,
		Role:      role,
		CreatedAt: time.Now(),
	}
	return token
}

func generateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Get returns the session for the token, or nil if not found.
func (m *Manager) Get(token string) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[token]
}

// Destroy removes a session.
func (m *Manager) Destroy(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
}

// RecordLoginAttempt records a failed login attempt for rate limiting.
func (m *Manager) RecordLoginAttempt(key string) *AttemptTracker {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.loginAttempts[key]
	if !ok {
		t = &AttemptTracker{}
		m.loginAttempts[key] = t
	}
	t.Count++
	t.LastFail = time.Now()
	return t
}

// GetLoginAttempts returns the attempt tracker for the key.
func (m *Manager) GetLoginAttempts(key string) *AttemptTracker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loginAttempts[key]
}

// ClearLoginAttempts resets attempts for the key (on successful login).
func (m *Manager) ClearLoginAttempts(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.loginAttempts, key)
}

// RecordResetAttempt records a failed password reset attempt.
func (m *Manager) RecordResetAttempt(key string) *AttemptTracker {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.resetAttempts[key]
	if !ok {
		t = &AttemptTracker{}
		m.resetAttempts[key] = t
	}
	t.Count++
	t.LastFail = time.Now()
	return t
}

// GetResetAttempts returns the reset attempt tracker for the key.
func (m *Manager) GetResetAttempts(key string) *AttemptTracker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.resetAttempts[key]
}

// ClearResetAttempts resets password reset attempts for the key.
func (m *Manager) ClearResetAttempts(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.resetAttempts, key)
}

// StartCleanup periodically removes expired sessions and stale attempt trackers.
func (m *Manager) StartCleanup(interval, sessionTTL, attemptTTL time.Duration) {
	m.stopCh = make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.cleanup(sessionTTL, attemptTTL)
			case <-m.stopCh:
				return
			}
		}
	}()
}

func (m *Manager) cleanup(sessionTTL, attemptTTL time.Duration) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	for token, sess := range m.sessions {
		if now.Sub(sess.CreatedAt) > sessionTTL {
			delete(m.sessions, token)
		}
	}
	for key, t := range m.loginAttempts {
		if now.Sub(t.LastFail) > attemptTTL {
			delete(m.loginAttempts, key)
		}
	}
	for key, t := range m.resetAttempts {
		if now.Sub(t.LastFail) > attemptTTL {
			delete(m.resetAttempts, key)
		}
	}
}

// Stop signals the cleanup goroutine to exit.
func (m *Manager) Stop() {
	if m.stopCh != nil {
		close(m.stopCh)
	}
}

type signedPayload struct {
	UserID   int    `json:"uid"`
	Username string `json:"usr"`
	Role     string `json:"rol"`
	Expiry   int64  `json:"exp"`
}

// CreateSigned returns a stateless HMAC-SHA256-signed token encoding the session claims.
// No server-side lookup is required for GetSigned validation.
func (m *Manager) CreateSigned(userID int, username, role string) string {
	payload := signedPayload{
		UserID:   userID,
		Username: username,
		Role:     role,
		Expiry:   time.Now().Add(24 * time.Hour).Unix(),
	}
	raw, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(raw)

	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return payloadB64 + "." + sigB64
}

// GetSigned validates the HMAC signature and expiry, then returns the embedded session.
// Returns nil if the token is malformed, tampered, or expired.
func (m *Manager) GetSigned(token string) *Session {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil
	}
	payloadB64, sigB64 := parts[0], parts[1]

	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payloadB64))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sigB64), []byte(expectedSig)) {
		return nil
	}

	raw, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil
	}

	var p signedPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil
	}
	if time.Now().Unix() > p.Expiry {
		return nil
	}

	return &Session{
		UserID:    p.UserID,
		Username:  p.Username,
		Role:      p.Role,
		CreatedAt: time.Now(),
	}
}
