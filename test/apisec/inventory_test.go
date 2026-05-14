package apisectest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
)

func TestLegacyMembersV0_DifficultyBehavior(t *testing.T) {
	app := newTestApp(t)
	cookie := app.sessionCookie(app.mustLogin(gordonUsername, gordonPassword))
	resp := doAPIRequest(t, app, http.MethodGet, "/api/v0/members/2", "", cookie)
	assertStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	assertContains(t, body, "password")
	assertContains(t, body, "secret_answer")

	mediumApp := newTestApp(t)
	mediumApp.setDifficulty(core.Medium)
	mediumCookie := mediumApp.sessionCookie(mediumApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, mediumApp, http.MethodGet, "/api/v0/members/2", "", mediumCookie)
	assertStatus(t, resp, http.StatusOK)
	if got := resp.Header.Get("Deprecation"); got != "true" {
		t.Fatalf("expected Deprecation header, got %q", got)
	}
	readBody(t, resp)

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	hardCookie := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, hardApp, http.MethodGet, "/api/v0/members/2", "", hardCookie)
	assertStatus(t, resp, http.StatusGone)
	readBody(t, resp)
}

func TestShadowAdminUsers_DifficultyBehavior(t *testing.T) {
	app := newTestApp(t)
	cookie := app.sessionCookie(app.mustLogin(gordonUsername, gordonPassword))
	resp := doAPIRequest(t, app, http.MethodGet, "/api/internal/users", "", cookie)
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, readBody(t, resp), "users")

	mediumApp := newTestApp(t)
	mediumApp.setDifficulty(core.Medium)
	mediumCookie := mediumApp.sessionCookie(mediumApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, mediumApp, http.MethodGet, "/api/internal/users", "", mediumCookie)
	assertStatus(t, resp, http.StatusForbidden)
	resp = doAPIRequestWithHeader(t, mediumApp, http.MethodGet, "/api/internal/users", "", map[string]string{"X-Internal": "true"}, mediumCookie)
	assertStatus(t, resp, http.StatusOK)
	readBody(t, resp)

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	userCookie := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	adminCookie := hardApp.sessionCookie(hardApp.mustLogin(adminUsername, adminPassword))
	resp = doAPIRequestWithHeader(t, hardApp, http.MethodGet, "/api/internal/users", "", map[string]string{"X-Internal": "true"}, userCookie)
	assertStatus(t, resp, http.StatusForbidden)
	resp = doAPIRequest(t, hardApp, http.MethodGet, "/api/internal/users", "", adminCookie)
	assertStatus(t, resp, http.StatusOK)
	readBody(t, resp)
}

func TestStaleOpenAPI_DifficultyBehavior(t *testing.T) {
	app := newTestApp(t)
	cookie := app.sessionCookie(app.mustLogin(gordonUsername, gordonPassword))
	resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/openapi.json", "", cookie)
	assertStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	assertContains(t, body, "/api/v0/members")
	assertContains(t, body, "/api/internal/users")

	mediumApp := newTestApp(t)
	mediumApp.setDifficulty(core.Medium)
	mediumCookie := mediumApp.sessionCookie(mediumApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, mediumApp, http.MethodGet, "/api/v1/openapi.json", "", mediumCookie)
	assertStatus(t, resp, http.StatusOK)
	body = readBody(t, resp)
	assertContains(t, body, "/api/internal/users")
	assertContains(t, body, "deprecated")

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	hardCookie := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, hardApp, http.MethodGet, "/api/v1/openapi.json", "", hardCookie)
	assertStatus(t, resp, http.StatusOK)
	body = readBody(t, resp)
	assertNotContains(t, body, "/api/v0/members")
	assertNotContains(t, body, "/api/internal/users")
}
