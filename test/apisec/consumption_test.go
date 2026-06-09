package apisectest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

func testSignature(body, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestPaymentWebhook_PublicAndDifficultyBehavior(t *testing.T) {
	app := newTestApp(t)
	resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/partners/payments/webhook", `{"invoice_id":2,"amount":149.5,"status":"paid"}`)
	assertStatus(t, resp, http.StatusOK)
	readBody(t, resp)

	mediumApp := newTestApp(t)
	mediumApp.setDifficulty(core.Medium)
	resp = doAPIRequest(t, mediumApp, http.MethodPost, "/api/v1/partners/payments/webhook", `{"invoice_id":2,"amount":149.5,"status":"paid"}`)
	assertStatus(t, resp, http.StatusUnauthorized)
	resp = doAPIRequestWithHeader(t, mediumApp, http.MethodPost, "/api/v1/partners/payments/webhook",
		`{"invoice_id":2,"amount":149.5,"status":"paid"}`, map[string]string{"X-Partner-Token": "partner-secret"})
	assertStatus(t, resp, http.StatusOK)
	readBody(t, resp)

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	body := `{"invoice_id":2,"amount":149.5,"status":"paid"}`
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/partners/payments/webhook", body)
	assertStatus(t, resp, http.StatusBadRequest)
	headers := map[string]string{
		"Idempotency-Key":     "evt-1",
		"X-Webhook-Signature": testSignature(body, "dvga-webhook-signing-secret"),
	}
	resp = doAPIRequestWithHeader(t, hardApp, http.MethodPost, "/api/v1/partners/payments/webhook", body, headers)
	assertStatus(t, resp, http.StatusOK)
	readBody(t, resp)
	resp = doAPIRequestWithHeader(t, hardApp, http.MethodPost, "/api/v1/partners/payments/webhook", body, headers)
	assertStatus(t, resp, http.StatusConflict)
}

func TestCRMProfileSync_DifficultyBehavior(t *testing.T) {
	app := newTestApp(t)
	cookie := app.sessionCookie(app.mustLogin(gordonUsername, gordonPassword))
	resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/partners/crm/profile", `{"user_id":2,"role":"admin"}`, cookie)
	assertStatus(t, resp, http.StatusOK)
	readBody(t, resp)
	var gordon database.User
	app.store.DB().First(&gordon, 2)
	if gordon.Role != "admin" {
		t.Fatalf("easy CRM sync did not trust role, got %q", gordon.Role)
	}

	mediumApp := newTestApp(t)
	mediumApp.setDifficulty(core.Medium)
	mediumCookie := mediumApp.sessionCookie(mediumApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, mediumApp, http.MethodPost, "/api/v1/partners/crm/profile",
		`{"user_id":3,"email":"pablo-updated@example.com","role":"admin"}`, mediumCookie)
	assertStatus(t, resp, http.StatusOK)
	readBody(t, resp)
	var pablo database.User
	mediumApp.store.DB().First(&pablo, 3)
	if pablo.Email != "pablo-updated@example.com" || pablo.Role == "admin" {
		t.Fatalf("medium CRM sync state mismatch: email=%q role=%q", pablo.Email, pablo.Role)
	}

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	hardCookie := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/partners/crm/profile",
		`{"user_id":3,"email":"blocked@example.com"}`, hardCookie)
	assertStatus(t, resp, http.StatusForbidden)
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/partners/crm/profile",
		`{"user_id":2,"email":"self@example.com","role":"admin"}`, hardCookie)
	assertStatus(t, resp, http.StatusOK)
	readBody(t, resp)
}

func TestShippingStatusSync_DifficultyBehavior(t *testing.T) {
	app := newTestApp(t)
	cookie := app.sessionCookie(app.mustLogin(gordonUsername, gordonPassword))
	resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/partners/shipping/status", `{"order_id":1,"status":"pending"}`, cookie)
	assertStatus(t, resp, http.StatusOK)
	readBody(t, resp)

	mediumApp := newTestApp(t)
	mediumApp.setDifficulty(core.Medium)
	mediumCookie := mediumApp.sessionCookie(mediumApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, mediumApp, http.MethodPost, "/api/v1/partners/shipping/status", `{"order_id":1,"status":"pending"}`, mediumCookie)
	assertStatus(t, resp, http.StatusUnauthorized)
	resp = doAPIRequestWithHeader(t, mediumApp, http.MethodPost, "/api/v1/partners/shipping/status",
		`{"order_id":1,"status":"pending"}`, map[string]string{"X-Carrier": "FastShip"}, mediumCookie)
	assertStatus(t, resp, http.StatusOK)
	readBody(t, resp)

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	hardCookie := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	invalidBody := `{"order_id":1,"status":"pending"}`
	resp = doAPIRequestWithHeader(t, hardApp, http.MethodPost, "/api/v1/partners/shipping/status",
		invalidBody, map[string]string{"X-Carrier-Signature": testSignature(invalidBody, "dvga-carrier-signing-secret")}, hardCookie)
	assertStatus(t, resp, http.StatusConflict)
	validBody := `{"order_id":2,"status":"shipped"}`
	resp = doAPIRequestWithHeader(t, hardApp, http.MethodPost, "/api/v1/partners/shipping/status",
		validBody, map[string]string{"X-Carrier-Signature": testSignature(validBody, "dvga-carrier-signing-secret")}, hardCookie)
	assertStatus(t, resp, http.StatusOK)
	readBody(t, resp)
}
