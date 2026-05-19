package ssrf

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"

	"DVGA/internal/core"
)

var hardAllowedHosts = map[string]bool{
	"example.com":        true,
	"www.example.com":    true,
	"hooks.example.com":  true,
	"images.example.com": true,
	"cdn.example.com":    true,
}

func parseTarget(raw string) (*url.URL, string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, "", err
	}
	return u, strings.ToLower(u.Hostname()), nil
}

func naiveBlockedHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "::1", "metadata.google.internal":
		return true
	default:
		return false
	}
}

func unsafeInternalHost(host string) bool {
	if host == "" {
		return true
	}
	if strings.Contains(host, "localhost") || strings.Contains(host, "metadata") || strings.Contains(host, "internal") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func validateHardOutbound(raw string) (*url.URL, error) {
	u, host, err := parseTarget(raw)
	if err != nil || u.Scheme == "" || host == "" {
		return nil, fmt.Errorf("invalid url")
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("scheme not allowed")
	}
	if unsafeInternalHost(host) {
		return nil, fmt.Errorf("internal hosts are blocked")
	}
	if !hardAllowedHosts[host] {
		return nil, fmt.Errorf("host not allowlisted")
	}
	return u, nil
}

func urlPreviewMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "url-preview",
		Name:       "URL Preview",
		Category:   "Server-Side Request Forgery",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
		},
		Hints: [4]string{
			"Ask the server to preview a URL.",
			"Try a link-local metadata address.",
			"Can the medium blocklist be bypassed?",
			"Hard mode requires an allowlisted external HTTPS host.",
		},
	}
}

func serveURLPreviewInfo(m *SSRFModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>URL Preview</h3>
<p>POST <code>/api/v1/tools/url-preview</code> with JSON body <code>{"url":"https://example.com/news"}</code>.</p>`)
}

func serveURLPreviewAPI(m *SSRFModule, w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	u, host, err := parseTarget(body.URL)
	if err != nil || u.Scheme == "" || host == "" {
		jsonError(w, "invalid url", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		json.NewEncoder(w).Encode(map[string]any{"status": "previewed", "url": body.URL, "host": host, "preview": simulatedPreview(host)})
	case core.Medium:
		if naiveBlockedHost(host) {
			jsonError(w, "host blocked", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "previewed", "url": body.URL, "host": host})
	case core.Hard:
		if _, err := validateHardOutbound(body.URL); err != nil {
			jsonError(w, err.Error(), http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "previewed", "url": body.URL, "host": host})
	}
}

func simulatedPreview(host string) string {
	if unsafeInternalHost(host) {
		return "internal service response: instance-id=i-123456"
	}
	return "external page preview"
}

func webhookTesterMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "webhook-tester",
		Name:       "Webhook Tester",
		Category:   "Server-Side Request Forgery",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
		},
		Hints: [4]string{
			"Send a webhook test to a supplied URL.",
			"Can the target be internal?",
			"Try a redirect to an internal URL.",
			"Hard mode validates the final redirect target.",
		},
	}
}

func serveWebhookTesterInfo(m *SSRFModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Webhook Tester</h3>
<p>POST <code>/api/v1/integrations/webhook/test</code> with JSON body <code>{"url":"https://hooks.example.com/test"}</code>.</p>`)
}

func serveWebhookTesterAPI(m *SSRFModule, w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL        string `json:"url"`
		RedirectTo string `json:"redirect_to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	u, _, err := parseTarget(body.URL)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		jsonError(w, "invalid url", http.StatusBadRequest)
		return
	}
	finalURL := body.URL
	if body.RedirectTo != "" {
		finalURL = body.RedirectTo
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		json.NewEncoder(w).Encode(map[string]any{"status": "sent", "requested_url": body.URL, "delivered_to": finalURL})
	case core.Medium:
		if u.Scheme != "http" && u.Scheme != "https" {
			jsonError(w, "scheme not allowed", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "sent", "requested_url": body.URL, "delivered_to": finalURL, "note": "redirect followed"})
	case core.Hard:
		if _, err := validateHardOutbound(body.URL); err != nil {
			jsonError(w, err.Error(), http.StatusForbidden)
			return
		}
		if body.RedirectTo != "" {
			if _, err := validateHardOutbound(body.RedirectTo); err != nil {
				jsonError(w, "redirect target blocked", http.StatusForbidden)
				return
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "sent", "requested_url": body.URL, "delivered_to": finalURL})
	}
}

func avatarImportMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:         "avatar-import",
		Name:       "Avatar Import",
		Category:   "Server-Side Request Forgery",
		Kind:       core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
		},
		Hints: [4]string{
			"Import an avatar from a remote image URL.",
			"Try internal hosts with image-looking paths.",
			"Is the extension the only validation?",
			"Hard mode validates host, content type, and size.",
		},
	}
}

func serveAvatarImportInfo(m *SSRFModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Avatar Import</h3>
<p>POST <code>/api/v1/members/avatar/import</code> with JSON body <code>{"image_url":"https://images.example.com/avatar.png"}</code>.</p>`)
}

func serveAvatarImportAPI(m *SSRFModule, w http.ResponseWriter, r *http.Request) {
	var body struct {
		ImageURL    string `json:"image_url"`
		ContentType string `json:"content_type"`
		Size        int    `json:"size"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	u, host, err := parseTarget(body.ImageURL)
	if err != nil || u.Scheme == "" || host == "" {
		jsonError(w, "invalid url", http.StatusBadRequest)
		return
	}
	ext := strings.ToLower(path.Ext(u.Path))
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		json.NewEncoder(w).Encode(map[string]any{"status": "imported", "image_url": body.ImageURL, "host": host})
	case core.Medium:
		if ext != ".png" && ext != ".jpg" && ext != ".jpeg" && ext != ".gif" {
			jsonError(w, "image extension required", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "imported", "image_url": body.ImageURL, "host": host, "validation": "extension-only"})
	case core.Hard:
		if _, err := validateHardOutbound(body.ImageURL); err != nil {
			jsonError(w, err.Error(), http.StatusForbidden)
			return
		}
		if !strings.HasPrefix(body.ContentType, "image/") {
			jsonError(w, "image content type required", http.StatusBadRequest)
			return
		}
		if body.Size <= 0 || body.Size > 1024*1024 {
			jsonError(w, "image size out of range", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "imported", "image_url": body.ImageURL, "host": host})
	}
}
