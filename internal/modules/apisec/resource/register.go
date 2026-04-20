package resource

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

// RegisterAll registers all Unrestricted Resource Consumption sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("report-generator", func(d core.Difficulty) core.VulnModule {
		return &ResourceModule{
			difficulty: d,
			meta:       reportGeneratorMeta(d),
			serveInfo:  serveReportGeneratorInfo,
			serveAPI:   serveReportGeneratorAPI,
			apiRoutes: []core.APIRouteSpec{
				{Method: http.MethodPost, Path: "/api/v1/reports/generate"},
			},
			store: store,
			sess:  sess,
		}
	})
	reg.Register("notification-blast", func(d core.Difficulty) core.VulnModule {
		return &ResourceModule{
			difficulty:      d,
			meta:            notificationBlastMeta(d),
			serveInfo:       serveNotificationBlastInfo,
			serveAPI:        serveNotificationBlastAPI,
			apiRoutes: []core.APIRouteSpec{
				{Method: http.MethodPost, Path: "/api/v1/notifications/send"},
			},
			store:           store,
			sess:            sess,
			IPCounters:      map[string]int{},
			AccountCounters: map[int]int{},
		}
	})
}
