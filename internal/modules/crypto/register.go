package crypto

import (
	"DVGA/internal/core"
	"DVGA/internal/database"
)

// RegisterAll registers all Cryptographic Failures sub-vulnerabilities.
func RegisterAll(reg *core.Registry, store *database.Store) {
	reg.Register("data-exposure", func(d core.Difficulty) core.VulnModule {
		return &CryptoModule{difficulty: d, meta: dataExposureMeta(d), serve: serveDataExposure, store: store}
	})
	reg.Register("weak-passwd", func(d core.Difficulty) core.VulnModule {
		return &CryptoModule{difficulty: d, meta: weakPasswdMeta(d), serve: serveWeakPasswd, store: store}
	})
}

