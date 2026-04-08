package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/pbkdf2"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

// --- Factory ---

type DataExposureFactory struct {
	store *database.Store
}

func (f *DataExposureFactory) Create(d core.Difficulty) core.VulnModule {
	return &DataExposureModule{difficulty: d, store: f.store}
}

// --- Module ---

type DataExposureModule struct {
	difficulty core.Difficulty
	store      *database.Store
}

func (m *DataExposureModule) Meta() core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "data-exposure",
		Name:        "Secure Notes",
		Description: "Store and manage your private notes.",
		Category:    "Cryptographic Failures",
		Difficulty:  m.difficulty,
		References: []string{
			"https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
		},
		Hints: [4]string{
			"How are your notes protected at rest?",
			"Intercept the response and examine the data format",
			"That encoding looks familiar — is it really encryption?",
			"Base64 decode the values to reveal plaintext",
		},
	}
}

func (m *DataExposureModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		if action == "add" {
			m.handleAdd(w, r)
			return
		}
		if action == "decrypt" {
			m.handleDecrypt(w, r)
			return
		}
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

func (m *DataExposureModule) handleAdd(w http.ResponseWriter, r *http.Request) {
	title := r.FormValue("title")
	value := r.FormValue("value")
	password := r.FormValue("password")

	if title == "" || value == "" {
		fmt.Fprint(w, m.renderForm("Title and value are required.", ""))
		return
	}

	var storedValue string
	switch m.difficulty {
	case core.Easy:
		storedValue = value
	case core.Medium:
		storedValue = base64.StdEncoding.EncodeToString([]byte(value))
	case core.Hard:
		if password == "" {
			fmt.Fprint(w, m.renderForm("Password required.", ""))
			return
		}
		encrypted, err := encryptAES(value, password)
		if err != nil {
			fmt.Fprint(w, m.renderForm("Encryption error.", ""))
			return
		}
		storedValue = encrypted
	}

	m.store.DB().Create(&database.Secret{UserID: 1, Title: title, Value: storedValue})
	m.ServeHTTP(w, r)
}

func (m *DataExposureModule) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	secretValue := r.FormValue("secret_value")
	password := r.FormValue("password")

	decrypted, err := decryptAES(secretValue, password)
	if err != nil {
		fmt.Fprint(w, m.renderForm("Decryption failed.", ""))
		return
	}
	resp, _ := json.Marshal(map[string]string{"decrypted": decrypted})
	fmt.Fprint(w, m.renderForm("", `<pre class="output">`+string(resp)+`</pre>`))
}

func (m *DataExposureModule) serveEasy(w http.ResponseWriter) {
	// VULNERABLE: plaintext display — but no label saying so
	var secrets []database.Secret
	m.store.DB().Find(&secrets)

	type note struct {
		ID      uint   `json:"id"`
		Owner   uint   `json:"owner"`
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	var notes []note
	for _, s := range secrets {
		notes = append(notes, note{ID: s.ID, Owner: s.UserID, Title: s.Title, Content: s.Value})
	}
	data, _ := json.MarshalIndent(map[string]interface{}{"notes": notes}, "", "  ")
	fmt.Fprint(w, m.renderForm("", `<pre class="output">`+string(data)+`</pre>`))
}

func (m *DataExposureModule) serveMedium(w http.ResponseWriter) {
	// WEAK: base64 — returned without labeling the encoding
	var secrets []database.Secret
	m.store.DB().Find(&secrets)

	type note struct {
		ID      uint   `json:"id"`
		Owner   uint   `json:"owner"`
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	var notes []note
	for _, s := range secrets {
		encoded := base64.StdEncoding.EncodeToString([]byte(s.Value))
		notes = append(notes, note{ID: s.ID, Owner: s.UserID, Title: s.Title, Content: encoded})
	}
	data, _ := json.MarshalIndent(map[string]interface{}{"notes": notes}, "", "  ")
	fmt.Fprint(w, m.renderForm("", `<pre class="output">`+string(data)+`</pre>`))
}

func (m *DataExposureModule) serveHard(w http.ResponseWriter) {
	// SECURE: AES-256-GCM encrypted values
	var secrets []database.Secret
	m.store.DB().Find(&secrets)

	type note struct {
		ID      uint   `json:"id"`
		Owner   uint   `json:"owner"`
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	var notes []note
	for _, s := range secrets {
		notes = append(notes, note{ID: s.ID, Owner: s.UserID, Title: s.Title, Content: truncate(s.Value, 30)})
	}
	data, _ := json.MarshalIndent(map[string]interface{}{"notes": notes}, "", "  ")

	output := `<pre class="output">` + string(data) + `</pre>`

	// Decrypt form
	output += `<div class="vuln-form" style="margin-top:1rem">
<h4>Decrypt a Note</h4>
<form method="POST">
<input type="hidden" name="action" value="decrypt" />
<label>Encrypted Value: <input type="text" name="secret_value" size="40" /></label><br/>
<label>Password: <input type="password" name="password" /></label>
<input type="submit" value="Decrypt" />
</form>
</div>`

	fmt.Fprint(w, m.renderForm("", output))
}

func (m *DataExposureModule) renderForm(errMsg, output string) string {
	html := `<div class="vuln-form">
<h3>Secure Notes</h3>
<form method="POST">
<input type="hidden" name="action" value="add" />
<label>Title: <input type="text" name="title" /></label><br/>
<label>Value: <input type="text" name="value" /></label><br/>`
	if m.difficulty == core.Hard {
		html += `<label>Password: <input type="password" name="password" /></label><br/>`
	}
	html += `<input type="submit" value="Add Note" />
</form>
</div>`
	if errMsg != "" {
		html += `<div class="error">` + errMsg + `</div>`
	}
	if output != "" {
		html += output
	}
	return html
}

// --- Crypto helpers ---

func encryptAES(plaintext, password string) (string, error) {
	key := pbkdf2.Key([]byte(password), []byte("dvga-salt"), 100000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptAES(encoded, password string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	key := pbkdf2.Key([]byte(password), []byte("dvga-salt"), 100000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
