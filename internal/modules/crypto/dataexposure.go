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

func dataExposureMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "data-exposure",
		Name:        "Secure Notes",
		Description: "Store and manage your private notes.",
		Category:    "Cryptographic Failures",
		Difficulty:  d,
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

func serveDataExposure(m *CryptoModule, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		switch r.FormValue("action") {
		case "add":
			deHandleAdd(m, w, r)
			return
		case "decrypt":
			deHandleDecrypt(m, w, r)
			return
		}
	}
	switch m.difficulty {
	case core.Easy:
		deEasy(m, w)
	case core.Medium:
		deMedium(m, w)
	case core.Hard:
		deHard(m, w)
	}
}

func deHandleAdd(m *CryptoModule, w http.ResponseWriter, r *http.Request) {
	title := r.FormValue("title")
	value := r.FormValue("value")
	password := r.FormValue("password")
	if title == "" || value == "" {
		fmt.Fprint(w, deRenderForm(m.difficulty, "Title and value are required.", ""))
		return
	}
	var stored string
	switch m.difficulty {
	case core.Easy:
		stored = value
	case core.Medium:
		stored = base64.StdEncoding.EncodeToString([]byte(value))
	case core.Hard:
		if password == "" {
			fmt.Fprint(w, deRenderForm(m.difficulty, "Password required.", ""))
			return
		}
		enc, err := encryptAES(value, password)
		if err != nil {
			fmt.Fprint(w, deRenderForm(m.difficulty, "Encryption error.", ""))
			return
		}
		stored = enc
	}
	m.store.DB().Create(&database.Secret{UserID: 1, Title: title, Value: stored})
	switch m.difficulty {
	case core.Easy:
		deEasy(m, w)
	case core.Medium:
		deMedium(m, w)
	case core.Hard:
		deHard(m, w)
	}
}

func deHandleDecrypt(m *CryptoModule, w http.ResponseWriter, r *http.Request) {
	secretValue := r.FormValue("secret_value")
	password := r.FormValue("password")
	decrypted, err := decryptAES(secretValue, password)
	if err != nil {
		fmt.Fprint(w, deRenderForm(m.difficulty, "Decryption failed.", ""))
		return
	}
	resp, _ := json.Marshal(map[string]string{"decrypted": decrypted})
	fmt.Fprint(w, deRenderForm(m.difficulty, "", `<pre class="output">`+string(resp)+`</pre>`))
}

// deRenderNotes loads all secrets and renders them as stored (no transform).
// Easy: stored as plaintext. Medium: stored as base64. Hard: stored as AES ciphertext.
func deRenderNotes(m *CryptoModule) string {
	var secrets []database.Secret
	m.store.DB().Find(&secrets)
	notes := deNotesJSON(secrets, func(v string) string { return v })
	return `<pre class="output">` + notes + `</pre>`
}

func deEasy(m *CryptoModule, w http.ResponseWriter) {
	fmt.Fprint(w, deRenderForm(m.difficulty, "", deRenderNotes(m)))
}

func deMedium(m *CryptoModule, w http.ResponseWriter) {
	fmt.Fprint(w, deRenderForm(m.difficulty, "", deRenderNotes(m)))
}

func deHard(m *CryptoModule, w http.ResponseWriter) {
	output := deRenderNotes(m)
	output += `<div class="vuln-form" style="margin-top:1rem">
<h4>Decrypt a Note</h4>
<form method="POST">
<input type="hidden" name="action" value="decrypt" />
<label>Encrypted Value: <input type="text" name="secret_value" size="40" /></label><br/>
<label>Password: <input type="password" name="password" /></label>
<input type="submit" value="Decrypt" />
</form>
</div>`
	fmt.Fprint(w, deRenderForm(m.difficulty, "", output))
}

func deNotesJSON(secrets []database.Secret, transform func(string) string) string {
	type note struct {
		ID      uint   `json:"id"`
		Owner   uint   `json:"owner"`
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	notes := make([]note, 0, len(secrets))
	for _, s := range secrets {
		notes = append(notes, note{ID: s.ID, Owner: s.UserID, Title: s.Title, Content: transform(s.Value)})
	}
	data, _ := json.MarshalIndent(map[string]any{"notes": notes}, "", "  ")
	return string(data)
}

func deRenderForm(d core.Difficulty, errMsg, output string) string {
	html := `<div class="vuln-form">
<h3>Secure Notes</h3>
<form method="POST">
<input type="hidden" name="action" value="add" />
<label>Title: <input type="text" name="title" /></label><br/>
<label>Value: <input type="text" name="value" /></label><br/>`
	if d == core.Hard {
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

// --- AES-256-GCM helpers ---

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
	plaintext, err := aesGCM.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
