package bola

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"DVGA/internal/core"
	"DVGA/internal/database"

	"github.com/go-chi/chi/v5"
)

func documentFetchMeta(d core.Difficulty) core.ModuleMeta {
	return core.ModuleMeta{
		ID:       "document-fetch",
		Name:     "Document Fetch",
		Category: "Broken Object Level Authorization",
		Kind:     core.KindAPI,
		Difficulty: d,
		References: []string{
			"https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
		},
		Hints: [4]string{
			"Documents are accessible via an API.",
			"Try fetching documents you don't own.",
			"The role cookie may be checked client-side.",
			"Classification 'confidential' should require ownership.",
		},
	}
}

func serveDocumentFetchInfo(m *BOLAModule, w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_id")
	userID := 0
	if cookie != nil {
		if sess := m.sess.Get(cookie.Value); sess != nil {
			userID = sess.UserID
		}
	}
	var docs []database.Document
	m.store.DB().Where("owner_user_id = ?", userID).Limit(5).Find(&docs)
	list := ""
	for _, d := range docs {
		list += fmt.Sprintf("<li>[%s] <a href='/api/v1/documents/%d'>%s</a></li>", d.Classification, d.ID, d.Title)
	}
	if list == "" {
		list = "<li>No documents. Try logging in.</li>"
	}
	fmt.Fprintf(w, `<h3>Your Documents</h3><ul>%s</ul>`, list)
}

func serveDocumentFetchAPI(m *BOLAModule, w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch m.difficulty {
	case core.Easy:
		// No auth
		var doc database.Document
		if err := m.store.DB().First(&doc, id).Error; err != nil {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(docJSON(doc))

	case core.Medium:
		// Checks role cookie (bypassable via header)
		roleCookie, _ := r.Cookie("role")
		if roleCookie == nil || (roleCookie.Value != "admin" && roleCookie.Value != "user") {
			jsonError(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		var doc database.Document
		if err := m.store.DB().First(&doc, id).Error; err != nil {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		// Checks role but not ownership
		json.NewEncoder(w).Encode(docJSON(doc))

	case core.Hard:
		// Server-side session + ownership
		cookie, err := r.Cookie("session_id")
		if err != nil {
			jsonError(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		sess := m.sess.Get(cookie.Value)
		if sess == nil {
			jsonError(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		var doc database.Document
		if err := m.store.DB().First(&doc, id).Error; err != nil {
			jsonError(w, "not found", http.StatusNotFound)
			return
		}
		if doc.Classification != "public" && sess.Role != "admin" && int(doc.OwnerUserID) != sess.UserID {
			jsonError(w, "forbidden", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(docJSON(doc))
	}
}

func docJSON(d database.Document) map[string]any {
	return map[string]any{
		"id": d.ID, "owner_user_id": d.OwnerUserID, "title": d.Title,
		"body": d.Body, "classification": d.Classification,
	}
}
