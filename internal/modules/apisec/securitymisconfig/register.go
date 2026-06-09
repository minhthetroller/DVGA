package securitymisconfig

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

// RegisterAll registers all Security Misconfiguration sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("debug-config", func(d core.Difficulty) core.VulnModule {
		return &SecurityMisconfigModule{
			difficulty: d,
			meta:       debugConfigMeta(d),
			serveInfo:  serveDebugConfigInfo,
			serveAPI:   serveDebugConfigAPI,
			apiRoutes:  []core.APIRouteSpec{{Method: http.MethodGet, Path: "/api/v1/system/debug"}},
			store:      store,
			sess:       sess,
		}
	})
	reg.Register("cors-policy", func(d core.Difficulty) core.VulnModule {
		return &SecurityMisconfigModule{
			difficulty: d,
			meta:       corsPolicyMeta(d),
			serveInfo:  serveCorsPolicyInfo,
			serveAPI:   serveCorsPolicyAPI,
			apiRoutes:  []core.APIRouteSpec{{Method: http.MethodGet, Path: "/api/v1/misconfig/cors"}},
			store:      store,
			sess:       sess,
		}
	})
	reg.Register("verbose-errors", func(d core.Difficulty) core.VulnModule {
		return &SecurityMisconfigModule{
			difficulty: d,
			meta:       verboseErrorsMeta(d),
			serveInfo:  serveVerboseErrorsInfo,
			serveAPI:   serveVerboseErrorsAPI,
			apiRoutes:  []core.APIRouteSpec{{Method: http.MethodGet, Path: "/api/v1/system/query"}},
			store:      store,
			sess:       sess,
		}
	})
}
