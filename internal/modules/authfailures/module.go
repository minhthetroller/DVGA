// Package authfailures implements Identification and Authentication Failures scenarios.
package authfailures

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *AuthFailuresModule, w http.ResponseWriter, r *http.Request)

// AuthFailuresModule handles all identification/authentication failure scenarios.
type AuthFailuresModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serve      scenarioFunc
	store      *database.Store
	sess       *session.Manager
}

func (m *AuthFailuresModule) Meta() core.ModuleMeta { return m.meta }

func (m *AuthFailuresModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serve(m, w, r)
}
