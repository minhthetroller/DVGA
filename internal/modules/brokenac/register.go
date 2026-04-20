package brokenac

import (
	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

// RegisterAll registers all Broken Access Control sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("idor", func(d core.Difficulty) core.VulnModule {
		return &BrokenACModule{difficulty: d, meta: idorMeta(d), serve: serveIDOR, store: store, sess: sess}
	})
	reg.Register("path-traversal", func(d core.Difficulty) core.VulnModule {
		return &BrokenACModule{difficulty: d, meta: pathTraversalMeta(d), serve: servePathTraversal}
	})
	reg.Register("privesc", func(d core.Difficulty) core.VulnModule {
		return &BrokenACModule{difficulty: d, meta: privEscMeta(d), serve: servePrivEsc, store: store, sess: sess}
	})
}

