package authfailurestest

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthFailuresRegisteredUnderExpectedCategory(t *testing.T) {
	app := newTestApp(t)
	cats := app.registry.Categories(core.Easy)

	var ids []string
	for _, mod := range cats["Identification and Authentication Failures"] {
		ids = append(ids, mod.Meta().ID)
	}

	assert.ElementsMatch(t, []string{"user-enumeration", "remember-me"}, ids)
}

func TestUserEnumerationByDifficulty(t *testing.T) {
	app := newTestApp(t)

	w := doModuleRequest(t, app, "user-enumeration", http.MethodPost, "/", formBody("username", "admin"))
	assert.Contains(t, w.Body.String(), `"exists":true`)
	w = doModuleRequest(t, app, "user-enumeration", http.MethodPost, "/", formBody("username", "not-a-user"))
	assert.Contains(t, w.Body.String(), `"exists":false`)

	app.setDifficulty(core.Medium)
	w = doModuleRequest(t, app, "user-enumeration", http.MethodPost, "/", formBody("username", "admin"))
	assert.Contains(t, w.Body.String(), `data-account-status="exists"`)
	w = doModuleRequest(t, app, "user-enumeration", http.MethodPost, "/", formBody("username", "not-a-user"))
	assert.Contains(t, w.Body.String(), `data-account-status="missing"`)

	app.setDifficulty(core.Hard)
	w = doModuleRequest(t, app, "user-enumeration", http.MethodPost, "/", formBody("username", "admin"))
	validBody := w.Body.String()
	w = doModuleRequest(t, app, "user-enumeration", http.MethodPost, "/", formBody("username", "not-a-user"))
	invalidBody := w.Body.String()
	assert.Equal(t, validBody, invalidBody)
	assert.NotContains(t, validBody, `data-account-status=`)
	assert.NotContains(t, validBody, `"exists":`)
	assert.NotContains(t, validBody, `"missing":`)
}

func TestRememberMeByDifficulty(t *testing.T) {
	app := newTestApp(t)

	easyToken := base64.StdEncoding.EncodeToString([]byte("1:admin:admin"))
	w := doModuleRequest(t, app, "remember-me", http.MethodPost, "/", formBody("action", "check"), &http.Cookie{Name: "remember_me", Value: easyToken})
	assert.Contains(t, w.Body.String(), "accepted unsigned cookie")
	assert.Contains(t, w.Body.String(), `"username":"admin"`)

	app.setDifficulty(core.Medium)
	payload := base64.StdEncoding.EncodeToString([]byte("1:admin:admin"))
	mediumToken := payload + "." + weakRememberSignature(payload)
	w = doModuleRequest(t, app, "remember-me", http.MethodPost, "/", formBody("action", "check"), &http.Cookie{Name: "remember_me", Value: mediumToken})
	assert.Contains(t, w.Body.String(), "accepted weak static signature")
	assert.Contains(t, w.Body.String(), `"role":"admin"`)

	app.setDifficulty(core.Hard)
	w = doModuleRequest(t, app, "remember-me", http.MethodPost, "/", formBody("action", "check"), &http.Cookie{Name: "remember_me", Value: easyToken})
	assert.Contains(t, w.Body.String(), "Invalid or expired")

	w = doModuleRequest(t, app, "remember-me", http.MethodPost, "/", formBody("action", "login", "username", "admin", "password", "admin"))
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.True(t, cookies[0].HttpOnly)
	w = doModuleRequest(t, app, "remember-me", http.MethodPost, "/", formBody("action", "check"), cookies[0])
	assert.Contains(t, w.Body.String(), "server-side token verified")
	assert.Contains(t, w.Body.String(), `"username":"admin"`)
}

func weakRememberSignature(payload string) string {
	mac := hmac.New(sha1.New, []byte("remember-secret"))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
