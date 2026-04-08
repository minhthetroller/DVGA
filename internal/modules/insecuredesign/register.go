package insecuredesign

import (
	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

// RegisterAll registers all Insecure Design sub-vulnerability factories.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("pwd-reset", &PwdResetFactory{store: store, sess: sess})
	reg.Register("brute-force", &BruteForceFactory{store: store, sess: sess})
}
