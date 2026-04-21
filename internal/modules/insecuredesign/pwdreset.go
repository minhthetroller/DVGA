package insecuredesign

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

func pwdResetMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "pwd-reset",
		Name:        "Forgot Password",
		Description: "Recover your account password.",
		Category:    "Insecure Design",
		Difficulty:  d,
		References: []string{
			"https://owasp.org/Top10/A04_2021-Insecure_Design/",
		},
		Hints: [4]string{
			"How many guesses for the security question?",
			"Is there a limit on attempts?",
			"Automate answer guessing",
			"No rate limiting — brute force the security answer",
		},
	}
}

func servePwdReset(m *InsecureDesignModule, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		switch r.FormValue("action") {
		case "lookup":
			prHandleLookup(m, w, r)
		case "answer":
			prHandleAnswer(m, w, r)
		case "use_token":
			prHandleUseToken(m, w, r)
		default:
			fmt.Fprint(w, prRenderLookup(""))
		}
		return
	}
	fmt.Fprint(w, prRenderLookup(""))
}

func prHandleLookup(m *InsecureDesignModule, w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	var user database.User
	if err := m.store.DB().Where("username = ?", username).First(&user).Error; err != nil {
		fmt.Fprint(w, prRenderLookup(`<div class="error">User not found.</div>`))
		return
	}
	fmt.Fprint(w, prRenderQuestion(user.Username, user.SecretQuestion, ""))
}

func prHandleAnswer(m *InsecureDesignModule, w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	answer := r.FormValue("answer")
	newPassword := r.FormValue("new_password")
	var user database.User
	if err := m.store.DB().Where("username = ?", username).First(&user).Error; err != nil {
		fmt.Fprint(w, prRenderLookup(`<div class="error">User not found.</div>`))
		return
	}
	key := username
	switch m.difficulty {
	case core.Easy:
		if !strings.EqualFold(answer, user.SecretAnswer) {
			fmt.Fprint(w, prRenderQuestion(username, user.SecretQuestion, `<div class="error">Wrong answer.</div>`))
			return
		}
		if newPassword == "" {
			fmt.Fprint(w, prRenderQuestion(username, user.SecretQuestion, `<div class="error">Provide a new password.</div>`))
			return
		}
		m.store.DB().Model(&user).Update("password", newPassword)
		resp, _ := json.Marshal(map[string]any{"success": true, "message": "Password reset successful"})
		fmt.Fprint(w, prRenderLookup(`<pre class="output">`+string(resp)+`</pre>`))

	case core.Medium:
		tracker := m.sess.GetResetAttempts(key)
		if tracker != nil && tracker.Count >= 15 && time.Since(tracker.LastFail) < time.Minute {
			fmt.Fprint(w, prRenderQuestion(username, user.SecretQuestion, `<div class="error">Too many attempts. Try again later.</div>`))
			return
		}
		if !strings.EqualFold(answer, user.SecretAnswer) {
			m.sess.RecordResetAttempt(key)
			fmt.Fprint(w, prRenderQuestion(username, user.SecretQuestion, `<div class="error">Wrong answer.</div>`))
			return
		}
		m.sess.ClearResetAttempts(key)
		if newPassword == "" {
			fmt.Fprint(w, prRenderQuestion(username, user.SecretQuestion, `<div class="error">Provide a new password.</div>`))
			return
		}
		m.store.DB().Model(&user).Update("password", newPassword)
		resp, _ := json.Marshal(map[string]any{"success": true, "message": "Password reset successful"})
		fmt.Fprint(w, prRenderLookup(`<pre class="output">`+string(resp)+`</pre>`))

	case core.Hard:
		tracker := m.sess.GetResetAttempts(key)
		if tracker != nil && tracker.Count >= 3 && time.Since(tracker.LastFail) < 15*time.Minute {
			remaining := 15*time.Minute - time.Since(tracker.LastFail)
			fmt.Fprint(w, prRenderQuestion(username, user.SecretQuestion,
				fmt.Sprintf(`<div class="error">Account locked. Try again in %d minutes.</div>`, int(remaining.Minutes())+1)))
			return
		}
		if tracker != nil && tracker.Count >= 3 && time.Since(tracker.LastFail) >= 15*time.Minute {
			m.sess.ClearResetAttempts(key)
		}
		if !strings.EqualFold(answer, user.SecretAnswer) {
			m.sess.RecordResetAttempt(key)
			fmt.Fprint(w, prRenderQuestion(username, user.SecretQuestion, `<div class="error">Wrong answer.</div>`))
			return
		}
		m.sess.ClearResetAttempts(key)
		tokenBytes := make([]byte, 16)
		rand.Read(tokenBytes)
		token := hex.EncodeToString(tokenBytes)
		m.store.DB().Create(&database.ResetToken{UserID: user.ID, Token: token, CreatedAt: time.Now()})
		fmt.Fprint(w, prRenderToken(username, token, ""))
	}
}

func prHandleUseToken(m *InsecureDesignModule, w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	token := r.FormValue("token")
	newPassword := r.FormValue("new_password")
	if newPassword == "" {
		fmt.Fprint(w, prRenderToken(username, token, `<div class="error">Provide a new password.</div>`))
		return
	}
	var resetToken database.ResetToken
	if err := m.store.DB().Where("token = ? AND used = ?", token, false).First(&resetToken).Error; err != nil {
		fmt.Fprint(w, prRenderLookup(`<div class="error">Invalid or expired token.</div>`))
		return
	}
	if time.Since(resetToken.CreatedAt) > 10*time.Minute {
		m.store.DB().Model(&resetToken).Update("used", true)
		fmt.Fprint(w, prRenderLookup(`<div class="error">Token expired.</div>`))
		return
	}
	m.store.DB().Model(&resetToken).Update("used", true)
	m.store.DB().Model(&database.User{}).Where("id = ?", resetToken.UserID).Update("password", newPassword)
	resp, _ := json.Marshal(map[string]any{"success": true, "message": "Password reset successful"})
	fmt.Fprint(w, prRenderLookup(`<pre class="output">`+string(resp)+`</pre>`))
}

func prRenderLookup(output string) string {
	html := `<div class="vuln-form">
<h3>Forgot Password</h3>
<p>Enter your username to recover your account:</p>
<form method="POST">
<input type="hidden" name="action" value="lookup" />
<label>Username: <input type="text" name="username" /></label>
<input type="submit" value="Continue" />
</form>
</div>`
	if output != "" {
		html += output
	}
	return html
}

func prRenderQuestion(username, question, output string) string {
	html := fmt.Sprintf(`<div class="vuln-form">
<h3>Security Question</h3>
<p><strong>%s</strong></p>
<form method="POST">
<input type="hidden" name="action" value="answer" />
<input type="hidden" name="username" value="%s" />
<label>Answer: <input type="text" name="answer" /></label><br/>
<label>New Password: <input type="password" name="new_password" /></label><br/>
<input type="submit" value="Reset Password" />
</form>
</div>`, question, username)
	if output != "" {
		html += output
	}
	return html
}

func prRenderToken(username, token, output string) string {
	html := fmt.Sprintf(`<div class="vuln-form">
<h3>Reset Token</h3>
<p>A reset token has been generated. Use it within 10 minutes.</p>
<form method="POST">
<input type="hidden" name="action" value="use_token" />
<input type="hidden" name="username" value="%s" />
<label>Token: <input type="text" name="token" value="%s" readonly size="40" /></label><br/>
<label>New Password: <input type="password" name="new_password" /></label><br/>
<input type="submit" value="Set New Password" />
</form>
</div>`, username, token)
	if output != "" {
		html += output
	}
	return html
}


