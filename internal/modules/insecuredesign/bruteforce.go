package insecuredesign

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

// --- Factory ---

type BruteForceFactory struct {
	store *database.Store
	sess  *session.Manager
}

func (f *BruteForceFactory) Create(d core.Difficulty) core.VulnModule {
	return &BruteForceModule{difficulty: d, store: f.store, sess: f.sess}
}

// --- Module ---

type BruteForceModule struct {
	difficulty core.Difficulty
	store      *database.Store
	sess       *session.Manager
}

func (m *BruteForceModule) Meta() core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "brute-force",
		Name:        "Account Login",
		Description: "Sign in to your account.",
		Category:    "Insecure Design",
		Difficulty:  m.difficulty,
		References: []string{
			"https://owasp.org/Top10/A04_2021-Insecure_Design/",
		},
		Hints: [4]string{
			"How many tries do you get?",
			"Is there a lockout mechanism?",
			"Automate login attempts with a wordlist",
			"No rate limiting — use hydra or burp intruder",
		},
	}
}

func (m *BruteForceModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		m.handleLogin(w, r)
		return
	}
	fmt.Fprint(w, m.renderForm(""))
}

func (m *BruteForceModule) handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	key := username

	switch m.difficulty {
	case core.Easy:
		m.loginEasy(w, username, password)
	case core.Medium:
		m.loginMedium(w, username, password, key)
	case core.Hard:
		m.loginHard(w, r, username, password, key)
	}
}

func (m *BruteForceModule) loginEasy(w http.ResponseWriter, username, password string) {
	// VULNERABLE: No rate limiting at all
	var user database.User
	err := m.store.DB().Where("username = ? AND password = ?", username, password).First(&user).Error
	if err != nil {
		resp, _ := json.Marshal(map[string]interface{}{"success": false, "message": "Invalid credentials"})
		fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(resp)+`</pre>`))
		return
	}
	resp, _ := json.Marshal(map[string]interface{}{"success": true, "message": "Welcome back, " + user.Username})
	fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(resp)+`</pre>`))
}

func (m *BruteForceModule) loginMedium(w http.ResponseWriter, username, password, key string) {
	tracker := m.sess.GetLoginAttempts(key)
	if tracker != nil && tracker.Count >= 10 && time.Since(tracker.LastFail) < 30*time.Second {
		remaining := 30*time.Second - time.Since(tracker.LastFail)
		resp, _ := json.Marshal(map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Account locked. Try again in %d seconds.", int(remaining.Seconds())+1),
		})
		fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(resp)+`</pre>`))
		return
	}
	if tracker != nil && tracker.Count >= 10 && time.Since(tracker.LastFail) >= 30*time.Second {
		m.sess.ClearLoginAttempts(key)
	}

	var user database.User
	err := m.store.DB().Where("username = ? AND password = ?", username, password).First(&user).Error
	if err != nil {
		m.sess.RecordLoginAttempt(key)
		resp, _ := json.Marshal(map[string]interface{}{"success": false, "message": "Invalid credentials"})
		fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(resp)+`</pre>`))
		return
	}
	m.sess.ClearLoginAttempts(key)
	resp, _ := json.Marshal(map[string]interface{}{"success": true, "message": "Welcome back, " + user.Username})
	fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(resp)+`</pre>`))
}

func (m *BruteForceModule) loginHard(w http.ResponseWriter, r *http.Request, username, password, key string) {
	ip := r.RemoteAddr
	ipKey := "ip:" + ip

	for _, k := range []string{key, ipKey} {
		tracker := m.sess.GetLoginAttempts(k)
		if tracker != nil {
			var lockDuration time.Duration
			switch {
			case tracker.Count >= 9:
				lockDuration = 2 * time.Hour
			case tracker.Count >= 6:
				lockDuration = 30 * time.Minute
			case tracker.Count >= 3:
				lockDuration = 5 * time.Minute
			}
			if lockDuration > 0 && time.Since(tracker.LastFail) < lockDuration {
				resp, _ := json.Marshal(map[string]interface{}{"success": false, "message": "Invalid credentials"})
				fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(resp)+`</pre>`))
				return
			}
			if lockDuration > 0 && time.Since(tracker.LastFail) >= lockDuration {
				m.sess.ClearLoginAttempts(k)
			}
		}
	}

	var user database.User
	err := m.store.DB().Where("username = ? AND password = ?", username, password).First(&user).Error
	if err != nil {
		m.sess.RecordLoginAttempt(key)
		m.sess.RecordLoginAttempt(ipKey)
		resp, _ := json.Marshal(map[string]interface{}{"success": false, "message": "Invalid credentials"})
		fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(resp)+`</pre>`))
		return
	}
	m.sess.ClearLoginAttempts(key)
	m.sess.ClearLoginAttempts(ipKey)
	resp, _ := json.Marshal(map[string]interface{}{"success": true, "message": "Welcome back, " + user.Username})
	fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(resp)+`</pre>`))
}

func (m *BruteForceModule) renderForm(output string) string {
	html := `<div class="vuln-form">
<h3>Account Login</h3>
<form method="POST">
<label>Username: <input type="text" name="username" /></label><br/>
<label>Password: <input type="password" name="password" /></label><br/>
<input type="submit" value="Sign In" />
</form>
</div>`
	if output != "" {
		html += output
	}
	return html
}
