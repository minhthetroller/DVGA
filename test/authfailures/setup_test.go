package authfailurestest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/modules/authfailures"
	"DVGA/internal/session"
)

type testApp struct {
	store      *database.Store
	sessions   *session.Manager
	registry   *core.Registry
	difficulty *core.SafeDifficulty
	t          *testing.T
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	store, err := database.NewStore(":memory:")
	if err != nil {
		t.Fatalf("newTestApp: open store: %v", err)
	}
	if err := store.AutoMigrate(); err != nil {
		t.Fatalf("newTestApp: migrate: %v", err)
	}
	if err := store.Seed(); err != nil {
		t.Fatalf("newTestApp: seed: %v", err)
	}
	sessions := session.NewManager()
	registry := core.NewRegistry()
	authfailures.RegisterAll(registry, store, sessions)
	return &testApp{
		store:      store,
		sessions:   sessions,
		registry:   registry,
		difficulty: core.NewSafeDifficulty(core.Easy),
		t:          t,
	}
}

func (a *testApp) setDifficulty(d core.Difficulty) { a.difficulty.Set(d) }

func (a *testApp) buildModule(id string) core.VulnModule {
	a.t.Helper()
	mod, err := a.registry.Build(id, a.difficulty.Get())
	if err != nil {
		a.t.Fatalf("buildModule(%q): %v", id, err)
	}
	return mod
}

func doModuleRequest(t *testing.T, app *testApp, id, method, rawURL string, body io.Reader, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, rawURL, body)
	if method == http.MethodPost && body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	app.buildModule(id).ServeHTTP(w, req)
	return w
}

func formBody(kvPairs ...string) io.Reader {
	if len(kvPairs)%2 != 0 {
		panic("formBody: must receive an even number of key-value arguments")
	}
	vals := url.Values{}
	for i := 0; i < len(kvPairs); i += 2 {
		vals.Set(kvPairs[i], kvPairs[i+1])
	}
	return strings.NewReader(vals.Encode())
}
