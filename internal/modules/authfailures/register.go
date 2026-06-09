package authfailures

import (
	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

// RegisterAll registers all Identification and Authentication Failures sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("user-enumeration", func(d core.Difficulty) core.VulnModule {
		return &AuthFailuresModule{difficulty: d, meta: userEnumerationMeta(d), serve: serveUserEnumeration, store: store, sess: sess}
	})
	reg.Register("remember-me", func(d core.Difficulty) core.VulnModule {
		return &AuthFailuresModule{difficulty: d, meta: rememberMeMeta(d), serve: serveRememberMe, store: store, sess: sess}
	})
}
