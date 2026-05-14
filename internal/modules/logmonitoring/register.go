package logmonitoring

import (
	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

// RegisterAll registers all Security Logging and Monitoring Failures sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store, sess *session.Manager) {
	reg.Register("login-audit", func(d core.Difficulty) core.VulnModule {
		return &LogMonitoringModule{difficulty: d, meta: loginAuditMeta(d), serve: serveLoginAudit, store: store, sess: sess}
	})
	reg.Register("log-tampering", func(d core.Difficulty) core.VulnModule {
		return &LogMonitoringModule{difficulty: d, meta: logTamperingMeta(d), serve: serveLogTampering, store: store, sess: sess}
	})
}
