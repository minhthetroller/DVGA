package ssrf

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

// RegisterAll registers all SSRF sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("url-preview", func(d core.Difficulty) core.VulnModule {
		return &SSRFModule{
			difficulty: d,
			meta:       urlPreviewMeta(d),
			serveInfo:  serveURLPreviewInfo,
			serveAPI:   serveURLPreviewAPI,
			apiRoutes:  []core.APIRouteSpec{{Method: http.MethodPost, Path: "/api/v1/tools/url-preview"}},
			store:      store,
			sess:       sess,
		}
	})
	reg.Register("webhook-tester", func(d core.Difficulty) core.VulnModule {
		return &SSRFModule{
			difficulty: d,
			meta:       webhookTesterMeta(d),
			serveInfo:  serveWebhookTesterInfo,
			serveAPI:   serveWebhookTesterAPI,
			apiRoutes:  []core.APIRouteSpec{{Method: http.MethodPost, Path: "/api/v1/integrations/webhook/test"}},
			store:      store,
			sess:       sess,
		}
	})
	reg.Register("avatar-import", func(d core.Difficulty) core.VulnModule {
		return &SSRFModule{
			difficulty: d,
			meta:       avatarImportMeta(d),
			serveInfo:  serveAvatarImportInfo,
			serveAPI:   serveAvatarImportAPI,
			apiRoutes:  []core.APIRouteSpec{{Method: http.MethodPost, Path: "/api/v1/members/avatar/import"}},
			store:      store,
			sess:       sess,
		}
	})
}
