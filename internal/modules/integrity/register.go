package integrity

import (
	"DVGA/internal/core"
	"DVGA/internal/session"
)

// RegisterAll registers all Software and Data Integrity Failures sub-vulnerabilities.
func RegisterAll(reg *core.Registry, sess *session.Manager) {
	reg.Register("plugin-update", func(d core.Difficulty) core.VulnModule {
		return &IntegrityModule{difficulty: d, meta: pluginUpdateMeta(d), serve: servePluginUpdate, sess: sess}
	})
	reg.Register("workflow-import", func(d core.Difficulty) core.VulnModule {
		return &IntegrityModule{difficulty: d, meta: workflowImportMeta(d), serve: serveWorkflowImport, sess: sess}
	})
}
