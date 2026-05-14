package integritytest

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
)

func TestIntegrityRegisteredUnderExpectedCategory(t *testing.T) {
	app := newTestApp(t)
	cats := app.registry.Categories(core.Easy)

	var ids []string
	for _, mod := range cats["Software and Data Integrity Failures"] {
		ids = append(ids, mod.Meta().ID)
	}

	assert.ElementsMatch(t, []string{"plugin-update", "workflow-import"}, ids)
}

func TestPluginUpdateByDifficulty(t *testing.T) {
	app := newTestApp(t)
	malicious := pluginManifestJSON("backup-agent", "9.9.9", "https://evil.example/plugin.zip", "")

	w := doModuleRequest(t, app, "plugin-update", http.MethodPost, "/", formBody("manifest", malicious))
	assert.Contains(t, w.Body.String(), `"accepted": true`)
	assert.Contains(t, w.Body.String(), "trusted without integrity verification")

	app.setDifficulty(core.Medium)
	url := "https://evil.example/plugin.zip"
	malicious = pluginManifestJSON("backup-agent", "9.9.9", url, simulatedPluginHash(url))
	w = doModuleRequest(t, app, "plugin-update", http.MethodPost, "/", formBody("manifest", malicious))
	assert.Contains(t, w.Body.String(), `"accepted": true`)
	assert.Contains(t, w.Body.String(), "attacker_checksum")

	app.setDifficulty(core.Hard)
	w = doModuleRequest(t, app, "plugin-update", http.MethodPost, "/", formBody("manifest", malicious))
	assert.Contains(t, w.Body.String(), `"accepted": false`)
	assert.Contains(t, w.Body.String(), "not trusted")

	approved := pluginManifestJSON(
		"calendar-sync",
		"1.4.2",
		"https://updates.dvga.local/plugins/calendar-sync-1.4.2.zip",
		"c78277c7e015f87ae351d7970037554ffd1503e03c209f465907224af9ea4122",
	)
	w = doModuleRequest(t, app, "plugin-update", http.MethodPost, "/", formBody("manifest", approved))
	assert.Contains(t, w.Body.String(), `"accepted": true`)
}

func TestWorkflowImportByDifficulty(t *testing.T) {
	app := newTestApp(t)
	payload := workflowPayload(99, "evil")

	w := doModuleRequest(t, app, "workflow-import", http.MethodPost, "/", formBody("payload", payload))
	assert.Contains(t, w.Body.String(), `"imported": true`)
	assert.Contains(t, w.Body.String(), "unsigned workflow accepted")

	app.setDifficulty(core.Medium)
	w = doModuleRequest(t, app, "workflow-import", http.MethodPost, "/", formBody("payload", payload))
	assert.Contains(t, w.Body.String(), "Invalid weak signature")
	w = doModuleRequest(t, app, "workflow-import", http.MethodPost, "/", formBody("payload", payload, "signature", weakWorkflowSignature(payload)))
	assert.Contains(t, w.Body.String(), `"imported": true`)
	assert.Contains(t, w.Body.String(), "static shared secret")

	app.setDifficulty(core.Hard)
	adminToken := app.sessions.Create(1, "admin", "admin")
	adminCookie := &http.Cookie{Name: "session_id", Value: adminToken}
	w = doModuleRequest(t, app, "workflow-import", http.MethodPost, "/", formBody("payload", payload, "signature", hardWorkflowSignature(payload)), adminCookie)
	assert.Contains(t, w.Body.String(), "owner does not match")

	ownedPayload := workflowPayload(1, "daily-report")
	w = doModuleRequest(t, app, "workflow-import", http.MethodPost, "/", formBody("payload", ownedPayload, "signature", hardWorkflowSignature(ownedPayload)), adminCookie)
	assert.Contains(t, w.Body.String(), `"imported": true`)
	assert.Contains(t, w.Body.String(), "session ownership verified")
}

func pluginManifestJSON(name, version, sourceURL, sha string) string {
	data, _ := json.Marshal(map[string]string{
		"name":    name,
		"version": version,
		"url":     sourceURL,
		"sha256":  sha,
	})
	return string(data)
}

func simulatedPluginHash(sourceURL string) string {
	sum := sha256.Sum256([]byte("payload from " + sourceURL))
	return hex.EncodeToString(sum[:])
}

func workflowPayload(ownerID int, name string) string {
	data, _ := json.Marshal(map[string]any{
		"id":       fmt.Sprintf("wf-%d", ownerID),
		"owner_id": ownerID,
		"name":     name,
		"action":   "run_command",
	})
	return base64.StdEncoding.EncodeToString(data)
}

func weakWorkflowSignature(payload string) string {
	sum := sha1.Sum([]byte("workflow-secret:" + payload))
	return hex.EncodeToString(sum[:])
}

func hardWorkflowSignature(payload string) string {
	mac := hmac.New(sha256.New, []byte("dvga-workflow-hard-key"))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
