package brokenauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

func mobileLoginMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:       "mobile-login",
		Name:     "Mobile Login",
		Category: "Broken Authentication",
		Kind:     core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
		},
		Hints: [4]string{
			"Authenticate to get a token.",
			"Decode the token — what format is it?",
			"Try altering the algorithm header.",
			"Accept any signature? Try alg:none.",
		},
	}
}

func serveMobileLoginInfo(m *BrokenAuthModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Mobile Login</h3>
<p>POST to <code>/api/v1/auth/token</code> with JSON body <code>{"username":"...","password":"..."}</code> to receive a token.</p>
<p>Use the token in the <code>Authorization: Bearer &lt;token&gt;</code> header.</p>`)
}

func serveMobileLoginAPI(m *BrokenAuthModule, w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	var user database.User
	if err := m.store.DB().Where("username = ? AND password = ?", creds.Username, creds.Password).First(&user).Error; err != nil {
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	var token string
	switch m.difficulty {
	case core.Easy:
		token = buildJWTNone(user)
	case core.Medium:
		token = buildJWTWeakHS256(user)
	case core.Hard:
		var err error
		token, err = buildJWTStrong(user, m.store)
		if err != nil {
			jsonError(w, "failed to generate token", http.StatusInternalServerError)
			return
		}
	}
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// Easy: alg:none — signature is empty, easily forged
func buildJWTNone(u database.User) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"sub":"%d","username":"%s","role":"%s"}`, u.ID, u.Username, u.Role)))
	return header + "." + payload + "."
}

// Medium: HS256 with "secret" key and no expiry
func buildJWTWeakHS256(u database.User) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"sub":"%d","username":"%s","role":"%s"}`, u.ID, u.Username, u.Role)))
	// Deliberately weak — use a predictable HMAC-like scheme
	sig := base64.RawURLEncoding.EncodeToString([]byte("signed-with-secret:" + header + "." + payload))
	return header + "." + payload + "." + sig
}

// Hard: store an opaque crypto/rand token in api_tokens table
func buildJWTStrong(u database.User, store *database.Store) (string, error) {
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(rawBytes)
	apiToken := database.ApiToken{
		UserID:    u.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Revoked:   false,
	}
	store.DB().Create(&apiToken)
	return token, nil
}

func sessionRenewalMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:       "session-renewal",
		Name:     "Session Renewal",
		Category: "Broken Authentication",
		Kind:     core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
		},
		Hints: [4]string{
			"A refresh endpoint issues new tokens.",
			"Decode the refresh token.",
			"Can you predict the next token?",
			"Try base64-decoding — is it just the user ID?",
		},
	}
}

func serveSessionRenewalInfo(m *BrokenAuthModule, w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h3>Session Renewal</h3>
<p>POST to <code>/api/v1/auth/refresh</code> with JSON body <code>{"refresh_token":"..."}</code> to obtain a new access token.</p>`)
}

func serveSessionRenewalAPI(m *BrokenAuthModule, w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		// base64(userID) — trivially decodable and forgeable
		decoded, err := base64.StdEncoding.DecodeString(body.RefreshToken)
		if err != nil {
			jsonError(w, "invalid token", http.StatusUnauthorized)
			return
		}
		userID, err := strconv.Atoi(strings.TrimSpace(string(decoded)))
		if err != nil {
			jsonError(w, "invalid token", http.StatusUnauthorized)
			return
		}
		newToken := base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(userID)))
		json.NewEncoder(w).Encode(map[string]string{"access_token": "access-" + newToken})

	case core.Medium:
		// Weak PRNG 8-char alphanumeric token stored in DB
		var apiToken database.ApiToken
		if err := m.store.DB().Where("token = ? AND revoked = ? AND expires_at > ?",
			body.RefreshToken, false, time.Now()).First(&apiToken).Error; err != nil {
			jsonError(w, "invalid token", http.StatusUnauthorized)
			return
		}
		newToken := weakToken(8)
		apiToken.Token = newToken
		apiToken.ExpiresAt = time.Now().Add(1 * time.Hour)
		m.store.DB().Save(&apiToken)
		json.NewEncoder(w).Encode(map[string]string{"access_token": newToken})

	case core.Hard:
		// Proper: one-time token, crypto/rand, revoked after use
		var apiToken database.ApiToken
		if err := m.store.DB().Where("token = ? AND revoked = ? AND expires_at > ?",
			body.RefreshToken, false, time.Now()).First(&apiToken).Error; err != nil {
			jsonError(w, "invalid token", http.StatusUnauthorized)
			return
		}
		apiToken.Revoked = true
		m.store.DB().Save(&apiToken)
		rawBytes := make([]byte, 32)
		if _, err := rand.Read(rawBytes); err != nil {
			jsonError(w, "internal server error", http.StatusInternalServerError)
			return
		}
		newTokenStr := base64.RawURLEncoding.EncodeToString(rawBytes)
		m.store.DB().Create(&database.ApiToken{
			UserID:    apiToken.UserID,
			Token:     newTokenStr,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		})
		json.NewEncoder(w).Encode(map[string]string{"access_token": newTokenStr})
	}
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func weakToken(n int) string {
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}
