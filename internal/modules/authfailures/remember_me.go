package authfailures

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

const rememberWeakSecret = "remember-secret"

func rememberMeMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "remember-me",
		Name:        "Remember Me Login",
		Description: "Persistent login using a remember-me cookie.",
		Category:    "Identification and Authentication Failures",
		Difficulty:  d,
		References: []string{
			"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
		},
		Hints: [4]string{
			"Persistent login cookies are authentication credentials.",
			"Decode the remember-me value.",
			"Static signing secrets can be guessed or leaked.",
			"Hard mode stores random server-side tokens.",
		},
	}
}

func serveRememberMe(m *AuthFailuresModule, w http.ResponseWriter, r *http.Request) {
	switch r.FormValue("action") {
	case "login":
		rmHandleLogin(m, w, r)
	case "check":
		rmHandleCheck(m, w, r)
	default:
		fmt.Fprint(w, rmRenderForm(""))
	}
}

func rmHandleLogin(m *AuthFailuresModule, w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	var user database.User
	if err := m.store.DB().Where("username = ? AND password = ?", username, password).First(&user).Error; err != nil {
		fmt.Fprint(w, rmRenderForm(`<div class="error">Invalid credentials.</div>`))
		return
	}

	token := ""
	switch m.difficulty {
	case core.Easy:
		token = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d:%s:%s", user.ID, user.Username, user.Role)))
	case core.Medium:
		payload := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d:%s:%s", user.ID, user.Username, user.Role)))
		token = payload + "." + rmWeakSignature(payload)
	case core.Hard:
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		token = hex.EncodeToString(raw)
		m.store.DB().Create(&database.RememberToken{
			UserID:    user.ID,
			Token:     token,
			ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
			CreatedAt: time.Now(),
		})
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "remember_me",
		Value:    token,
		Path:     "/",
		HttpOnly: m.difficulty == core.Hard,
		SameSite: http.SameSiteLaxMode,
	})
	resp, _ := json.Marshal(map[string]any{"remembered": true, "username": user.Username})
	fmt.Fprint(w, rmRenderForm(`<pre class="output">`+string(resp)+`</pre>`))
}

func rmHandleCheck(m *AuthFailuresModule, w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("remember_me")
	if err != nil || cookie.Value == "" {
		fmt.Fprint(w, rmRenderForm(`<div class="error">No remember-me cookie supplied.</div>`))
		return
	}

	switch m.difficulty {
	case core.Easy:
		parts, ok := rmDecodeEasy(cookie.Value)
		if !ok {
			fmt.Fprint(w, rmRenderForm(`<div class="error">Invalid remember-me cookie.</div>`))
			return
		}
		rmRenderRemembered(w, parts[1], parts[2], "accepted unsigned cookie")
	case core.Medium:
		pieces := strings.Split(cookie.Value, ".")
		if len(pieces) != 2 || !hmac.Equal([]byte(pieces[1]), []byte(rmWeakSignature(pieces[0]))) {
			fmt.Fprint(w, rmRenderForm(`<div class="error">Invalid remember-me signature.</div>`))
			return
		}
		parts, ok := rmDecodeEasy(pieces[0])
		if !ok {
			fmt.Fprint(w, rmRenderForm(`<div class="error">Invalid remember-me cookie.</div>`))
			return
		}
		rmRenderRemembered(w, parts[1], parts[2], "accepted weak static signature")
	case core.Hard:
		var token database.RememberToken
		err := m.store.DB().Where("token = ? AND revoked = ? AND expires_at > ?", cookie.Value, false, time.Now()).First(&token).Error
		if err != nil {
			fmt.Fprint(w, rmRenderForm(`<div class="error">Invalid or expired remember-me token.</div>`))
			return
		}
		var user database.User
		if err := m.store.DB().First(&user, token.UserID).Error; err != nil {
			fmt.Fprint(w, rmRenderForm(`<div class="error">Remembered user not found.</div>`))
			return
		}
		rmRenderRemembered(w, user.Username, user.Role, "server-side token verified")
	}
}

func rmDecodeEasy(token string) ([]string, bool) {
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, false
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 3 {
		return nil, false
	}
	if _, err := strconv.Atoi(parts[0]); err != nil {
		return nil, false
	}
	return parts, true
}

func rmWeakSignature(payload string) string {
	mac := hmac.New(sha1.New, []byte(rememberWeakSecret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func rmRenderRemembered(w http.ResponseWriter, username, role, note string) {
	resp, _ := json.Marshal(map[string]any{"remembered": true, "username": username, "role": role, "note": note})
	fmt.Fprint(w, rmRenderForm(`<pre class="output">`+string(resp)+`</pre>`))
}

func rmRenderForm(output string) string {
	page := `<div class="vuln-form">
<h3>Remember Me Login</h3>
<form method="POST">
<input type="hidden" name="action" value="login" />
<label>Username: <input type="text" name="username" /></label><br/>
<label>Password: <input type="password" name="password" /></label><br/>
<input type="submit" value="Sign In and Remember" />
</form>
<form method="POST" style="margin-top:1rem">
<input type="hidden" name="action" value="check" />
<input type="submit" value="Check Remembered User" />
</form>
</div>`
	if output != "" {
		page += output
	}
	return page
}
