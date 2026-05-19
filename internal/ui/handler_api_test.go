package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/modules/apisec/brokenauth"
	"DVGA/internal/modules/apisec/resource"
	"DVGA/internal/session"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIRouteAuthReturnsJSONInsteadOfLoginRedirect(t *testing.T) {
	handler := newAPIHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/send",
		strings.NewReader(`{"recipient":"user@example.com","body":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Routes().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	assert.JSONEq(t, `{"error":"unauthenticated"}`, w.Body.String())
	assert.NotContains(t, w.Body.String(), "<html")
}

func TestAuthTokenAPIRouteRemainsPublic(t *testing.T) {
	handler := newAPIHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token",
		strings.NewReader(`{"username":"admin","password":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Routes().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	assert.Contains(t, w.Body.String(), `"token"`)
}

func TestNotificationBlastHardQuotaPersistsAcrossMountedAPIRequests(t *testing.T) {
	handler := newAPIHandler(t)
	handler.difficulty.Set(core.Hard)
	token := handler.sessions.Create(2, "gordonb", "user")

	for i := 0; i < 5; i++ {
		w := postNotification(t, handler, token)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	w := postNotification(t, handler, token)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "quota exceeded")
}

func newAPIHandler(t *testing.T) *Handler {
	t.Helper()

	store, err := database.NewStore(":memory:")
	require.NoError(t, err)
	require.NoError(t, store.AutoMigrate())
	require.NoError(t, store.Seed())

	sessions := session.NewManager()
	registry := core.NewRegistry()
	resource.RegisterAll(registry, store, sessions)
	brokenauth.RegisterAll(registry, store, sessions)

	renderer, err := NewRenderer("templates")
	require.NoError(t, err)

	return NewHandler(
		renderer,
		registry,
		core.NewChain(),
		store,
		sessions,
		core.NewSafeDifficulty(core.Easy),
		"static",
		zerolog.Nop(),
	)
}

func postNotification(t *testing.T, handler *Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/notifications/send",
		strings.NewReader(`{"recipient":"user@example.com","body":"hello"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "session_id", Value: token})
	w := httptest.NewRecorder()
	handler.Routes().ServeHTTP(w, req)
	return w
}
