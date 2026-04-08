package crypto

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

// --- Factory ---

type WeakPasswdFactory struct {
	store *database.Store
}

func (f *WeakPasswdFactory) Create(d core.Difficulty) core.VulnModule {
	return &WeakPasswdModule{difficulty: d, store: f.store}
}

// --- Module ---

type WeakPasswdModule struct {
	difficulty core.Difficulty
	store      *database.Store
}

func (m *WeakPasswdModule) Meta() core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "weak-passwd",
		Name:        "Admin Console",
		Description: "Administration user listing.",
		Category:    "Cryptographic Failures",
		Difficulty:  m.difficulty,
		References: []string{
			"https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
		},
		Hints: [4]string{
			"The API response might include more than you expect",
			"Examine every field in the JSON response",
			"That hash is only 32 hex characters — what algorithm?",
			"MD5 with no salt — use rainbow tables or hashcat",
		},
	}
}

func (m *WeakPasswdModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.FormValue("action") == "verify" {
		m.handleVerify(w, r)
		return
	}

	switch m.difficulty {
	case core.Easy:
		m.serveEasy(w)
	case core.Medium:
		m.serveMedium(w)
	case core.Hard:
		m.serveHard(w)
	}
}

func (m *WeakPasswdModule) serveEasy(w http.ResponseWriter) {
	// VULNERABLE: includes plaintext password in API response
	var users []database.User
	m.store.DB().Find(&users)

	type userResp struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	var results []userResp
	for _, u := range users {
		results = append(results, userResp{ID: u.ID, Username: u.Username, Role: u.Role, Password: u.Password})
	}
	data, _ := json.MarshalIndent(map[string]interface{}{"users": results}, "", "  ")
	fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(data)+`</pre>`))
}

func (m *WeakPasswdModule) serveMedium(w http.ResponseWriter) {
	// WEAK: MD5 hashed passwords (no salt) — algorithm not labeled
	var users []database.User
	m.store.DB().Find(&users)

	type userResp struct {
		ID           uint   `json:"id"`
		Username     string `json:"username"`
		Role         string `json:"role"`
		PasswordHash string `json:"password_hash"`
	}
	var results []userResp
	for _, u := range users {
		hash := fmt.Sprintf("%x", md5.Sum([]byte(u.Password)))
		results = append(results, userResp{ID: u.ID, Username: u.Username, Role: u.Role, PasswordHash: hash})
	}
	data, _ := json.MarshalIndent(map[string]interface{}{"users": results}, "", "  ")
	fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(data)+`</pre>`))
}

func (m *WeakPasswdModule) serveHard(w http.ResponseWriter) {
	// SECURE: bcrypt hashes, masked display
	var users []database.User
	m.store.DB().Find(&users)

	type userResp struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	var results []userResp
	for _, u := range users {
		results = append(results, userResp{ID: u.ID, Username: u.Username, Role: u.Role})
	}
	data, _ := json.MarshalIndent(map[string]interface{}{"users": results}, "", "  ")

	output := `<pre class="output">` + string(data) + `</pre>`
	output += `<div class="vuln-form" style="margin-top:1rem">
<h4>Verify Password</h4>
<form method="POST">
<input type="hidden" name="action" value="verify" />
<label>Username: <input type="text" name="username" /></label>
<label>Password: <input type="password" name="guess" /></label>
<input type="submit" value="Verify" />
</form>
</div>`

	fmt.Fprint(w, m.renderForm(output))
}

func (m *WeakPasswdModule) handleVerify(w http.ResponseWriter, r *http.Request) {
	guess := r.FormValue("guess")
	username := r.FormValue("username")

	var user database.User
	if err := m.store.DB().Where("username = ?", username).First(&user).Error; err != nil {
		fmt.Fprint(w, m.renderForm(`<div class="error">User not found.</div>`))
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
	err := bcrypt.CompareHashAndPassword(hash, []byte(guess))
	if err == nil {
		resp, _ := json.Marshal(map[string]interface{}{"verified": true, "username": username})
		fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(resp)+`</pre>`))
	} else {
		resp, _ := json.Marshal(map[string]interface{}{"verified": false, "username": username})
		fmt.Fprint(w, m.renderForm(`<pre class="output">`+string(resp)+`</pre>`))
	}
}

func (m *WeakPasswdModule) renderForm(output string) string {
	html := `<div class="vuln-form">
<h3>Admin Console</h3>
<p>User administration panel.</p>
</div>`
	if output != "" {
		html += output
	}
	return html
}
