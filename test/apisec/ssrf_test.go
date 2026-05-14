package apisectest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
)

func TestURLPreview_DifficultyBehavior(t *testing.T) {
	app := newTestApp(t)
	cookie := app.sessionCookie(app.mustLogin(gordonUsername, gordonPassword))
	resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/tools/url-preview", `{"url":"http://169.254.169.254/latest/meta-data"}`, cookie)
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, readBody(t, resp), "internal service response")

	mediumApp := newTestApp(t)
	mediumApp.setDifficulty(core.Medium)
	mediumCookie := mediumApp.sessionCookie(mediumApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, mediumApp, http.MethodPost, "/api/v1/tools/url-preview", `{"url":"http://169.254.169.254/latest/meta-data"}`, mediumCookie)
	assertStatus(t, resp, http.StatusForbidden)
	resp = doAPIRequest(t, mediumApp, http.MethodPost, "/api/v1/tools/url-preview", `{"url":"http://169.254.169.254.evil.test/latest/meta-data"}`, mediumCookie)
	assertStatus(t, resp, http.StatusOK)

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	hardCookie := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/tools/url-preview", `{"url":"http://169.254.169.254/latest/meta-data"}`, hardCookie)
	assertStatus(t, resp, http.StatusForbidden)
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/tools/url-preview", `{"url":"https://example.com/news"}`, hardCookie)
	assertStatus(t, resp, http.StatusOK)
}

func TestWebhookTester_RedirectValidation(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	cookie := app.sessionCookie(app.mustLogin(gordonUsername, gordonPassword))
	resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/integrations/webhook/test",
		`{"url":"https://hooks.example.com/test","redirect_to":"http://169.254.169.254/latest/meta-data"}`, cookie)
	assertStatus(t, resp, http.StatusOK)
	assertContains(t, readBody(t, resp), "169.254.169.254")

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	hardCookie := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/integrations/webhook/test",
		`{"url":"https://hooks.example.com/test","redirect_to":"http://169.254.169.254/latest/meta-data"}`, hardCookie)
	assertStatus(t, resp, http.StatusForbidden)
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/integrations/webhook/test",
		`{"url":"https://hooks.example.com/test"}`, hardCookie)
	assertStatus(t, resp, http.StatusOK)
}

func TestAvatarImport_DifficultyBehavior(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	cookie := app.sessionCookie(app.mustLogin(gordonUsername, gordonPassword))
	resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/members/avatar/import",
		`{"image_url":"http://169.254.169.254/avatar.png"}`, cookie)
	assertStatus(t, resp, http.StatusOK)

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	hardCookie := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/members/avatar/import",
		`{"image_url":"http://169.254.169.254/avatar.png","content_type":"image/png","size":2048}`, hardCookie)
	assertStatus(t, resp, http.StatusForbidden)
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/members/avatar/import",
		`{"image_url":"https://images.example.com/avatar.png","content_type":"image/png","size":2048}`, hardCookie)
	assertStatus(t, resp, http.StatusOK)
}
