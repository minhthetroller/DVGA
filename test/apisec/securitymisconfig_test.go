package apisectest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
)

func TestDebugConfig_DifficultyBehavior(t *testing.T) {
	app := newTestApp(t)
	cookie := app.sessionCookie(app.mustLogin(gordonUsername, gordonPassword))
	resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/system/debug", "", cookie)
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, readBody(t, resp), "admin_password")

	mediumApp := newTestApp(t)
	mediumApp.setDifficulty(core.Medium)
	mediumCookie := mediumApp.sessionCookie(mediumApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, mediumApp, http.MethodGet, "/api/v1/system/debug", "", mediumCookie)
	assertStatus(t, resp, http.StatusOK)
	assertNotContains(t, readBody(t, resp), "sample_secret")
	resp = doAPIRequestWithHeader(t, mediumApp, http.MethodGet, "/api/v1/system/debug", "", map[string]string{"X-Debug": "true"}, mediumCookie)
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, readBody(t, resp), "sample_secret")

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	userCookie := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	adminCookie := hardApp.sessionCookie(hardApp.mustLogin(adminUsername, adminPassword))
	resp = doAPIRequest(t, hardApp, http.MethodGet, "/api/v1/system/debug", "", userCookie)
	assertStatus(t, resp, http.StatusForbidden)
	resp = doAPIRequest(t, hardApp, http.MethodGet, "/api/v1/system/debug", "", adminCookie)
	assertStatus(t, resp, http.StatusOK)
	body := readBody(t, resp)
	assertContains(t, body, "[redacted]")
	assertNotContains(t, body, `"admin_password":"admin"`)
}

func TestCORSPolicy_DifficultyBehavior(t *testing.T) {
	app := newTestApp(t)
	cookie := app.sessionCookie(app.mustLogin(gordonUsername, gordonPassword))
	resp := doAPIRequestWithHeader(t, app, http.MethodGet, "/api/v1/misconfig/cors", "", map[string]string{"Origin": "https://evil.test"}, cookie)
	assertStatus(t, resp, http.StatusOK)
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://evil.test" {
		t.Fatalf("easy CORS reflected %q", got)
	}
	readBody(t, resp)

	mediumApp := newTestApp(t)
	mediumApp.setDifficulty(core.Medium)
	mediumCookie := mediumApp.sessionCookie(mediumApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequestWithHeader(t, mediumApp, http.MethodGet, "/api/v1/misconfig/cors", "", map[string]string{"Origin": "https://evilcorp.local"}, mediumCookie)
	assertStatus(t, resp, http.StatusOK)
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://evilcorp.local" {
		t.Fatalf("medium CORS suffix bypass reflected %q", got)
	}
	readBody(t, resp)

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	hardCookie := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequestWithHeader(t, hardApp, http.MethodGet, "/api/v1/misconfig/cors", "", map[string]string{"Origin": "https://evilcorp.local"}, hardCookie)
	assertStatus(t, resp, http.StatusOK)
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("hard CORS should not reflect evil origin, got %q", got)
	}
	readBody(t, resp)
	resp = doAPIRequestWithHeader(t, hardApp, http.MethodGet, "/api/v1/misconfig/cors", "", map[string]string{"Origin": "https://app.corp.local"}, hardCookie)
	assertStatus(t, resp, http.StatusOK)
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.corp.local" {
		t.Fatalf("hard CORS did not allow app origin, got %q", got)
	}
	readBody(t, resp)
}

func TestVerboseErrors_DifficultyBehavior(t *testing.T) {
	app := newTestApp(t)
	cookie := app.sessionCookie(app.mustLogin(gordonUsername, gordonPassword))
	resp := doAPIRequest(t, app, http.MethodGet, "/api/v1/system/query?table=missing_table", "", cookie)
	assertStatus(t, resp, http.StatusInternalServerError)
	assertContains(t, readBody(t, resp), "no such table")

	mediumApp := newTestApp(t)
	mediumApp.setDifficulty(core.Medium)
	mediumCookie := mediumApp.sessionCookie(mediumApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, mediumApp, http.MethodGet, "/api/v1/system/query?table=missing_table", "", mediumCookie)
	assertStatus(t, resp, http.StatusInternalServerError)
	assertNotContains(t, readBody(t, resp), "no such table")
	resp = doAPIRequest(t, mediumApp, http.MethodGet, "/api/v1/system/query?table=missing_table&debug=true", "", mediumCookie)
	assertStatus(t, resp, http.StatusInternalServerError)
	assertContains(t, readBody(t, resp), "no such table")

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	hardCookie := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, hardApp, http.MethodGet, "/api/v1/system/query?table=missing_table&debug=true", "", hardCookie)
	assertStatus(t, resp, http.StatusInternalServerError)
	assertNotContains(t, readBody(t, resp), "no such table")
}
