// Package testutil provides shared test infrastructure for DVGA integration tests.
package testutil

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/modules/apisec/bfla"
	"DVGA/internal/modules/apisec/bola"
	"DVGA/internal/modules/apisec/bopla"
	"DVGA/internal/modules/apisec/brokenauth"
	"DVGA/internal/modules/apisec/resource"
	"DVGA/internal/modules/brokenac"
	"DVGA/internal/modules/crypto"
	"DVGA/internal/modules/injection"
	"DVGA/internal/modules/insecuredesign"
	"DVGA/internal/modules/misconfig"
	"DVGA/internal/session"

	"github.com/go-chi/chi/v5"
)

// Seed user credentials that match internal/database/seed.go
const (
	AdminUsername = "admin"
	AdminPassword = "admin"
	AdminID       = 1

	GordonUsername = "gordonb"
	GordonPassword = "abc123"
	GordonID       = 2

	PabloUsername = "pablo"
	PabloPassword = "letmein"
	PabloID       = 3

	LeetUsername = "1337"
	LeetPassword = "charley"
	LeetID       = 4

	HelpdeskUsername = "helpdesk"
	HelpdeskPassword = "help1234"
	HelpdeskID       = 5

	SupportUsername = "support"
	SupportPassword = "support1"
	SupportID       = 6
)

// TestApp is a fully wired test instance backed by an in-memory SQLite store.
// Each call to NewTestApp creates isolated state (DB, sessions, difficulty).
type TestApp struct {
	Store      *database.Store
	Sessions   *session.Manager
	Registry   *core.Registry
	Difficulty *core.SafeDifficulty
	Server     *httptest.Server
	t          *testing.T
	modCache   map[string]core.VulnModule // keyed as "id:difficulty"
	modMu      sync.Mutex
}

// NewTestApp creates a fresh TestApp for a single test or subtest.
// The test server is closed via t.Cleanup automatically.
func NewTestApp(t *testing.T) *TestApp {
	t.Helper()

	store, err := database.NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewTestApp: open store: %v", err)
	}
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("NewTestApp: migrate: %v", err)
	}
	if err := store.Seed(); err != nil {
		t.Fatalf("NewTestApp: seed: %v", err)
	}

	sessions := session.NewManager()
	difficulty := core.NewSafeDifficulty(core.Easy)
	registry := core.NewRegistry()

	brokenac.RegisterAll(registry, store, sessions)
	crypto.RegisterAll(registry, store)
	injection.RegisterAll(registry, store)
	insecuredesign.RegisterAll(registry, store, sessions)
	misconfig.RegisterAll(registry, store)
	bola.RegisterAll(registry, store, sessions)
	brokenauth.RegisterAll(registry, store, sessions)
	bopla.RegisterAll(registry, store, sessions)
	resource.RegisterAll(registry, store, sessions)
	bfla.RegisterAll(registry, store, sessions)

	app := &TestApp{
		Store:      store,
		Sessions:   sessions,
		Registry:   registry,
		Difficulty: difficulty,
		t:          t,
		modCache:   make(map[string]core.VulnModule),
	}

	r := app.buildRouter()
	app.Server = httptest.NewServer(r)
	t.Cleanup(func() { app.Server.Close() })

	return app
}

// SetDifficulty changes the active difficulty for subsequent module builds.
func (a *TestApp) SetDifficulty(d core.Difficulty) { a.Difficulty.Set(d) }

// Login creates a server-side session for the given credentials directly
// (no HTTP round-trip required). Returns the session token and true on success.
func (a *TestApp) Login(username, password string) (string, bool) {
	var user database.User
	if err := a.Store.DB().Where("username = ? AND password = ?", username, password).
		First(&user).Error; err != nil {
		return "", false
	}
	token := a.Sessions.Create(int(user.ID), user.Username, user.Role)
	return token, true
}

// MustLogin is like Login but fatals if the credentials are invalid.
func (a *TestApp) MustLogin(username, password string) string {
	a.t.Helper()
	token, ok := a.Login(username, password)
	if !ok {
		a.t.Fatalf("MustLogin: rejected credentials for %q", username)
	}
	return token
}

// SessionCookie wraps a token in an http.Cookie ready to attach to requests.
func (a *TestApp) SessionCookie(token string) *http.Cookie {
	return &http.Cookie{Name: "session_id", Value: token}
}

// BuildModule creates a VulnModule at the current difficulty via the registry.
func (a *TestApp) BuildModule(id string) core.VulnModule {
	a.t.Helper()
	m, err := a.Registry.Build(id, a.Difficulty.Get())
	if err != nil {
		a.t.Fatalf("BuildModule(%q): %v", id, err)
	}
	return m
}

// requireAuth is the test middleware — returns 401 JSON instead of redirecting.
func (a *TestApp) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil || cookie.Value == "" {
			http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}
		if a.Sessions.Get(cookie.Value) == nil {
			http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// buildRouter constructs a chi router with all API routes mounted.
// Routes are registered once at startup; difficulty is applied per-request.
func (a *TestApp) buildRouter() chi.Router {
	r := chi.NewRouter()

	for _, id := range a.Registry.IDs() {
		mod, err := a.Registry.Build(id, a.Difficulty.Get())
		if err != nil {
			continue
		}
		apiMod, ok := mod.(core.APIModule)
		if !ok {
			continue
		}
		// Capture instance once — preserves in-memory state (counters, etc.) across requests.
		_ = mod
		for _, rt := range apiMod.APIRoutes() {
			path := rt.Path
			modID := id
			// Auth endpoints are themselves the login mechanism — no auth middleware.
			isAuthPath := path == "/api/v1/auth/token" || path == "/api/v1/auth/refresh"
			handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				d := a.Difficulty.Get()
				cacheKey := fmt.Sprintf("%s:%d", modID, d)
				a.modMu.Lock()
				cached, found := a.modCache[cacheKey]
				if !found {
					m, err := a.Registry.Build(modID, d)
					if err != nil {
						a.modMu.Unlock()
						http.NotFound(w, req)
						return
					}
					a.modCache[cacheKey] = m
					cached = m
				}
				a.modMu.Unlock()
				if am, ok := cached.(core.APIModule); ok {
					am.ServeAPI(w, req)
				}
			})
			if isAuthPath {
				r.Method(rt.Method, path, handler)
			} else {
				r.With(a.requireAuth).Method(rt.Method, path, handler)
			}
		}
	}

	return r
}
