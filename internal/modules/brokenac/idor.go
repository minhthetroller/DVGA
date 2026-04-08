package brokenac

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

// --- Factory ---

type IDORFactory struct {
	store *database.Store
	sess  *session.Manager
}

func (f *IDORFactory) Create(d core.Difficulty) core.VulnModule {
	return &IDORModule{
		difficulty: d,
		store:      f.store,
		sess:       f.sess,
	}
}

// --- Module ---

type IDORModule struct {
	difficulty core.Difficulty
	store      *database.Store
	sess       *session.Manager
}

func (m *IDORModule) Meta() core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "idor",
		Name:        "My Profile",
		Description: "View your user profile.",
		Category:    "Broken Access Control",
		Difficulty:  m.difficulty,
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		},
		Hints: [4]string{
			"Whose data is this?",
			"Change the identifier in the request",
			"Try other users' IDs",
			"Access ?user_id=2 to view another user's data",
		},
	}
}

func (m *IDORModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userIDStr := r.FormValue("user_id")
	if userIDStr == "" {
		fmt.Fprint(w, m.renderForm(""))
		return
	}

	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		fmt.Fprint(w, m.renderForm(`<div class="error">Invalid user ID.</div>`))
		return
	}

	switch m.difficulty {
	case core.Easy:
		m.serveEasy(w, userID)
	case core.Medium:
		m.serveMedium(w, r, userID)
	case core.Hard:
		m.serveHard(w, r, userID)
	}
}

func (m *IDORModule) serveEasy(w http.ResponseWriter, userID int) {
	// No authorization check at all
	var user database.User
	if err := m.store.DB().First(&user, userID).Error; err != nil {
		fmt.Fprint(w, m.renderForm(`<div class="error">Profile not found.</div>`))
		return
	}
	var secrets []database.Secret
	m.store.DB().Where("user_id = ?", userID).Find(&secrets)
	fmt.Fprint(w, m.renderForm(formatProfileJSON(user, secrets)))
}

func (m *IDORModule) serveMedium(w http.ResponseWriter, r *http.Request, userID int) {
	// Checks role cookie (client-side trust)
	roleCookie, err := r.Cookie("role")
	if err != nil || roleCookie.Value != "admin" {
		fmt.Fprint(w, m.renderForm(`<div class="error">Access denied.</div>`))
		return
	}
	var user database.User
	if err := m.store.DB().First(&user, userID).Error; err != nil {
		fmt.Fprint(w, m.renderForm(`<div class="error">Profile not found.</div>`))
		return
	}
	var secrets []database.Secret
	m.store.DB().Where("user_id = ?", userID).Find(&secrets)
	fmt.Fprint(w, m.renderForm(formatProfileJSON(user, secrets)))
}

func (m *IDORModule) serveHard(w http.ResponseWriter, r *http.Request, userID int) {
	// Server-side RBAC via session
	cookie, err := r.Cookie("session_id")
	if err != nil {
		fmt.Fprint(w, m.renderForm(`<div class="error">Not authenticated.</div>`))
		return
	}
	sess := m.sess.Get(cookie.Value)
	if sess == nil {
		fmt.Fprint(w, m.renderForm(`<div class="error">Session expired.</div>`))
		return
	}
	if sess.Role != "admin" && sess.UserID != userID {
		fmt.Fprint(w, m.renderForm(`<div class="error">Access denied.</div>`))
		return
	}
	var user database.User
	if err := m.store.DB().First(&user, userID).Error; err != nil {
		fmt.Fprint(w, m.renderForm(`<div class="error">Profile not found.</div>`))
		return
	}
	var secrets []database.Secret
	m.store.DB().Where("user_id = ?", userID).Find(&secrets)
	fmt.Fprint(w, m.renderForm(formatProfileJSON(user, secrets)))
}

func formatProfileJSON(user database.User, secrets []database.Secret) string {
	type secretItem struct {
		Title string `json:"title"`
		Value string `json:"value"`
	}
	type profile struct {
		ID       uint         `json:"id"`
		Username string       `json:"username"`
		Role     string       `json:"role"`
		Data     []secretItem `json:"data,omitempty"`
	}
	p := profile{ID: user.ID, Username: user.Username, Role: user.Role}
	for _, s := range secrets {
		p.Data = append(p.Data, secretItem{Title: s.Title, Value: s.Value})
	}
	data, _ := json.MarshalIndent(map[string]interface{}{"profile": p}, "", "  ")
	return `<pre class="output">` + string(data) + `</pre>`
}

func (m *IDORModule) renderForm(output string) string {
	html := `<div class="vuln-form">
<h3>My Profile</h3>
<p>Enter your user ID to view your profile:</p>
<form method="GET">
<label>User ID: <input type="text" name="user_id" /></label>
<input type="submit" value="View Profile" />
</form>
</div>`
	if output != "" {
		html += output
	}
	return html
}
