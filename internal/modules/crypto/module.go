package crypto

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
)

type scenarioFunc func(m *CryptoModule, w http.ResponseWriter, r *http.Request)

// CryptoModule handles all Cryptographic Failures sub-scenarios.
type CryptoModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serve      scenarioFunc
	store      *database.Store
}

func (m *CryptoModule) Meta() core.ModuleMeta { return m.meta }

func (m *CryptoModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serve(m, w, r)
}
