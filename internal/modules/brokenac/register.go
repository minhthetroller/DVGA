package brokenac

import (
	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

// RegisterAll registers all Broken Access Control sub-vulnerability factories.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("idor", &IDORFactory{store: store, sess: sess})
	reg.Register("path-traversal", &PathTraversalFactory{})
	reg.Register("privesc", &PrivEscFactory{store: store, sess: sess})
}
