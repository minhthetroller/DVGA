package insecuredesign

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

func bruteForceMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "brute-force",
		Name:        "Account Login",
		Description: "Sign in to your account.",
		Category:    "Insecure Design",
		Difficulty:  d,
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

func serveBruteForce(m *InsecureDesignModule, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		bfHandleLogin(m, w, r)
		return
	}
	fmt.Fprint(w, bfRenderForm(""))
}

func bfHandleLogin(m *InsecureDesignModule, w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	key := username
	switch m.difficulty {
	case core.Easy:
		bfLoginEasy(m, w, username, password)
	case core.Medium:
		bfLoginMedium(m, w, username, password, key)
	case core.Hard:
		bfLoginHard(m, w, r, username, password, key)
	}
}

func bfLoginEasy(m *InsecureDesignModule, w http.ResponseWriter, username, password string) {
	var user database.User
	err := m.store.DB().Where("username = ? AND password = ?", username, password).First(&user).Error
	if err != nil {
		resp, _ := json.Marshal(map[string]any{"success": false, "message": "Invalid credentials"})
		fmt.Fprint(w, bfRenderForm(`<pre class="output">`+string(resp)+`</pre>`))
		return
	}
	resp, _ := json.Marshal(map[string]any{"success": true, "message": "Welcome back, " + user.Username})
	fmt.Fprint(w, bfRenderForm(`<pre class="output">`+string(resp)+`</pre>`))
}

func bfLoginMedium(m *InsecureDesignModule, w http.ResponseWriter, username, password, key string) {
	tracker := m.sess.GetLoginAttempts(key)
	if tracker != nil && tracker.Count >= 10 && time.Since(tracker.LastFail) < 30*time.Second {
		remaining := 30*time.Second - time.Since(tracker.LastFail)
		resp, _ := json.Marshal(map[string]any{
			"success": false,
			"message": fmt.Sprintf("Account locked. Try again in %d seconds.", int(remaining.Seconds())+1),
		})
		fmt.Fprint(w, bfRenderForm(`<pre class="output">`+string(resp)+`</pre>`))
		return
	}
	if tracker != nil && tracker.Count >= 10 && time.Since(tracker.LastFail) >= 30*time.Second {
		m.sess.ClearLoginAttempts(key)
	}
	var user database.User
	if err := m.store.DB().Where("username = ? AND password = ?", username, password).First(&user).Error; err != nil {
		m.sess.RecordLoginAttempt(key)
		resp, _ := json.Marshal(map[string]any{"success": false, "message": "Invalid credentials"})
		fmt.Fprint(w, bfRenderForm(`<pre class="output">`+string(resp)+`</pre>`))
		return
	}
	m.sess.ClearLoginAttempts(key)
	resp, _ := json.Marshal(map[string]any{"success": true, "message": "Welcome back, " + user.Username})
	fmt.Fprint(w, bfRenderForm(`<pre class="output">`+string(resp)+`</pre>`))
}

func bfLoginHard(m *InsecureDesignModule, w http.ResponseWriter, r *http.Request, username, password, key string) {
	ip := r.RemoteAddr
	ipKey := "ip:" + ip
	for _, k := range []string{key, ipKey} {
		tracker := m.sess.GetLoginAttempts(k)
		if tracker == nil {
			continue
		}
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
			resp, _ := json.Marshal(map[string]any{"success": false, "message": "Invalid credentials"})
			fmt.Fprint(w, bfRenderForm(`<pre class="output">`+string(resp)+`</pre>`))
			return
		}
		if lockDuration > 0 && time.Since(tracker.LastFail) >= lockDuration {
			m.sess.ClearLoginAttempts(k)
		}
	}
	var user database.User
	if err := m.store.DB().Where("username = ? AND password = ?", username, password).First(&user).Error; err != nil {
		m.sess.RecordLoginAttempt(key)
		m.sess.RecordLoginAttempt(ipKey)
		resp, _ := json.Marshal(map[string]any{"success": false, "message": "Invalid credentials"})
		fmt.Fprint(w, bfRenderForm(`<pre class="output">`+string(resp)+`</pre>`))
		return
	}
	m.sess.ClearLoginAttempts(key)
	m.sess.ClearLoginAttempts(ipKey)
	resp, _ := json.Marshal(map[string]any{"success": true, "message": "Welcome back, " + user.Username})
	fmt.Fprint(w, bfRenderForm(`<pre class="output">`+string(resp)+`</pre>`))
}

func bfRenderForm(output string) string {
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


