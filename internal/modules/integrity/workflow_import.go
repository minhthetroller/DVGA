package integrity

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"

	"DVGA/internal/core"
)

const (
	workflowWeakSecret = "workflow-secret"
	workflowHardSecret = "dvga-workflow-hard-key"
)

func workflowImportMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:          "workflow-import",
		Name:        "Workflow Import",
		Description: "Import automation workflows from a signed package.",
		Category:    "Software and Data Integrity Failures",
		Difficulty:  d,
		References: []string{
			"https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
		},
		Hints: [4]string{
			"Imported data can change application behavior.",
			"Is the package signed at all?",
			"Weak static signatures are still forgeable.",
			"Hard mode binds signatures to server trust and user ownership.",
		},
	}
}

type workflowPackage struct {
	ID      string `json:"id"`
	OwnerID int    `json:"owner_id"`
	Name    string `json:"name"`
	Action  string `json:"action"`
}

func serveWorkflowImport(m *IntegrityModule, w http.ResponseWriter, r *http.Request) {
	payload := r.FormValue("payload")
	signature := r.FormValue("signature")
	if payload == "" {
		fmt.Fprint(w, wiRenderForm(defaultWorkflowPayload(), "", ""))
		return
	}

	workflow, err := decodeWorkflow(payload)
	if err != nil {
		fmt.Fprint(w, wiRenderForm(payload, signature, `<div class="error">Invalid workflow package.</div>`))
		return
	}

	switch m.difficulty {
	case core.Easy:
		wiRenderResult(w, payload, signature, map[string]any{
			"imported": true,
			"workflow": workflow,
			"note":     "unsigned workflow accepted",
		})
	case core.Medium:
		if signature == "" || signature != weakWorkflowSignature(payload) {
			fmt.Fprint(w, wiRenderForm(payload, signature, `<div class="error">Invalid weak signature.</div>`))
			return
		}
		wiRenderResult(w, payload, signature, map[string]any{
			"imported": true,
			"workflow": workflow,
			"note":     "workflow accepted with a static shared secret",
		})
	case core.Hard:
		cookie, err := r.Cookie("session_id")
		if err != nil {
			fmt.Fprint(w, wiRenderForm(payload, signature, `<div class="error">Unauthenticated.</div>`))
			return
		}
		sess := m.sess.Get(cookie.Value)
		if sess == nil {
			fmt.Fprint(w, wiRenderForm(payload, signature, `<div class="error">Unauthenticated.</div>`))
			return
		}
		if signature == "" || signature != hardWorkflowSignature(payload) {
			fmt.Fprint(w, wiRenderForm(payload, signature, `<div class="error">Invalid trusted signature.</div>`))
			return
		}
		if workflow.OwnerID != sess.UserID {
			fmt.Fprint(w, wiRenderForm(payload, signature, `<div class="error">Workflow owner does not match current session.</div>`))
			return
		}
		wiRenderResult(w, payload, signature, map[string]any{
			"imported": true,
			"workflow": workflow,
			"note":     "trusted signature and session ownership verified",
		})
	}
}

func decodeWorkflow(payload string) (workflowPackage, error) {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return workflowPackage{}, err
	}
	var workflow workflowPackage
	if err := json.Unmarshal(raw, &workflow); err != nil {
		return workflowPackage{}, err
	}
	return workflow, nil
}

func weakWorkflowSignature(payload string) string {
	sum := sha1.Sum([]byte(workflowWeakSecret + ":" + payload))
	return hex.EncodeToString(sum[:])
}

func hardWorkflowSignature(payload string) string {
	mac := hmac.New(sha256.New, []byte(workflowHardSecret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func defaultWorkflowPayload() string {
	workflow := workflowPackage{ID: "wf-1001", OwnerID: 1, Name: "Daily Report", Action: "send_report"}
	data, _ := json.Marshal(workflow)
	return base64.StdEncoding.EncodeToString(data)
}

func wiRenderResult(w http.ResponseWriter, payload, signature string, result map[string]any) {
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Fprint(w, wiRenderForm(payload, signature, `<pre class="output">`+string(data)+`</pre>`))
}

func wiRenderForm(payload, signature, output string) string {
	page := `<div class="vuln-form">
<h3>Workflow Import</h3>
<p>Import a base64 encoded automation workflow package.</p>
<form method="POST">
<label>Payload</label><br/>
<textarea name="payload" rows="5" cols="90">` + html.EscapeString(payload) + `</textarea><br/>
<label>Signature: <input type="text" name="signature" value="` + html.EscapeString(signature) + `" size="80" /></label><br/>
<input type="submit" value="Import Workflow" />
</form>
</div>`
	if output != "" {
		page += output
	}
	return page
}
