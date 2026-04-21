package brokenauth

import (
	"encoding/json"
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// RegisterAll registers all Broken Authentication sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("mobile-login", func(d core.Difficulty) core.VulnModule {
		return &BrokenAuthModule{
			difficulty: d,
			meta:       mobileLoginMeta(d),
			serveInfo:  serveMobileLoginInfo,
			serveAPI:   serveMobileLoginAPI,
			apiRoutes: []core.APIRouteSpec{
				{Method: http.MethodPost, Path: "/api/v1/auth/token"},
			},
			store: store,
			sess:  sess,
		}
	})
	reg.Register("session-renewal", func(d core.Difficulty) core.VulnModule {
		return &BrokenAuthModule{
			difficulty: d,
			meta:       sessionRenewalMeta(d),
			serveInfo:  serveSessionRenewalInfo,
			serveAPI:   serveSessionRenewalAPI,
			apiRoutes: []core.APIRouteSpec{
				{Method: http.MethodPost, Path: "/api/v1/auth/refresh"},
			},
			store: store,
			sess:  sess,
		}
	})
}
