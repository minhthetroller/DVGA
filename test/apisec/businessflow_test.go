package apisectest

import (
	"net/http"
	"testing"

	"DVGA/internal/core"
)

func TestAPISecExpansion_RegistryBuildsNewModules(t *testing.T) {
	app := newTestApp(t)
	ids := []string{
		"promo-code-redemption",
		"flash-sale-reservation",
		"order-cancellation-window",
		"url-preview",
		"webhook-tester",
		"avatar-import",
		"debug-config",
		"cors-policy",
		"verbose-errors",
		"legacy-members-v0",
		"shadow-admin-users",
		"stale-openapi",
		"payment-webhook",
		"crm-profile-sync",
		"shipping-status-sync",
	}
	for _, d := range allDifficulties() {
		for _, id := range ids {
			mod, err := app.registry.Build(id, d)
			if err != nil {
				t.Fatalf("Build(%q, %v): %v", id, d, err)
			}
			if mod.Meta().Kind != core.KindAPI {
				t.Fatalf("%s should be an API module", id)
			}
		}
	}
}

func TestPromoCodeRedemption_MediumSessionBypassAndHardAccountLimit(t *testing.T) {
	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	token1 := app.mustLogin(gordonUsername, gordonPassword)
	cookie1 := app.sessionCookie(token1)

	resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/promotions/redeem", `{"code":"SPRING50"}`, cookie1)
	assertStatus(t, resp, http.StatusOK)
	resp = doAPIRequest(t, app, http.MethodPost, "/api/v1/promotions/redeem", `{"code":"SPRING50"}`, cookie1)
	assertStatus(t, resp, http.StatusConflict)

	token2 := app.mustLogin(gordonUsername, gordonPassword)
	cookie2 := app.sessionCookie(token2)
	resp = doAPIRequest(t, app, http.MethodPost, "/api/v1/promotions/redeem", `{"code":"SPRING50"}`, cookie2)
	assertStatus(t, resp, http.StatusOK)

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	hardCookie1 := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	hardCookie2 := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/promotions/redeem", `{"code":"SPRING50"}`, hardCookie1)
	assertStatus(t, resp, http.StatusOK)
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/promotions/redeem", `{"code":"SPRING50"}`, hardCookie2)
	assertStatus(t, resp, http.StatusConflict)
}

func TestFlashSaleReservation_DifficultyBehavior(t *testing.T) {
	app := newTestApp(t)
	cookie := app.sessionCookie(app.mustLogin(gordonUsername, gordonPassword))

	resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/events/1/reserve", `{"quantity":99}`, cookie)
	assertStatus(t, resp, http.StatusOK)

	mediumApp := newTestApp(t)
	mediumApp.setDifficulty(core.Medium)
	mediumCookie := mediumApp.sessionCookie(mediumApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, mediumApp, http.MethodPost, "/api/v1/events/1/reserve", `{"quantity":3}`, mediumCookie)
	assertStatus(t, resp, http.StatusBadRequest)
	resp = doAPIRequest(t, mediumApp, http.MethodPost, "/api/v1/events/1/reserve", `{"quantity":2}`, mediumCookie)
	assertStatus(t, resp, http.StatusOK)
	resp = doAPIRequest(t, mediumApp, http.MethodPost, "/api/v1/events/1/reserve", `{"quantity":2}`, mediumCookie)
	assertStatus(t, resp, http.StatusOK)

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	hardCookie := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/events/1/reserve", `{"quantity":2}`, hardCookie)
	assertStatus(t, resp, http.StatusOK)
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/events/1/reserve", `{"quantity":1}`, hardCookie)
	assertStatus(t, resp, http.StatusTooManyRequests)
}

func TestOrderCancellationWindow_DifficultyBehavior(t *testing.T) {
	app := newTestApp(t)
	cookie := app.sessionCookie(app.mustLogin(gordonUsername, gordonPassword))
	resp := doAPIRequest(t, app, http.MethodPost, "/api/v1/orders/1/cancel", `{}`, cookie)
	assertStatus(t, resp, http.StatusOK)

	mediumApp := newTestApp(t)
	mediumApp.setDifficulty(core.Medium)
	mediumCookie := mediumApp.sessionCookie(mediumApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, mediumApp, http.MethodPost, "/api/v1/orders/1/cancel", `{"status":"pending","within_window":true}`, mediumCookie)
	assertStatus(t, resp, http.StatusOK)

	hardApp := newTestApp(t)
	hardApp.setDifficulty(core.Hard)
	hardCookie := hardApp.sessionCookie(hardApp.mustLogin(gordonUsername, gordonPassword))
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/orders/1/cancel", `{"status":"pending","within_window":true}`, hardCookie)
	assertStatus(t, resp, http.StatusConflict)
	resp = doAPIRequest(t, hardApp, http.MethodPost, "/api/v1/orders/2/cancel", `{}`, hardCookie)
	assertStatus(t, resp, http.StatusOK)
}
