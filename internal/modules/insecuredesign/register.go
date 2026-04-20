package insecuredesign

import (
	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

// RegisterAll registers all Insecure Design sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("pwd-reset", func(d core.Difficulty) core.VulnModule {
		return &InsecureDesignModule{difficulty: d, meta: pwdResetMeta(d), serve: servePwdReset, store: store, sess: sess}
	})
	reg.Register("brute-force", func(d core.Difficulty) core.VulnModule {
		return &InsecureDesignModule{difficulty: d, meta: bruteForceMeta(d), serve: serveBruteForce, store: store, sess: sess}
	})
}

