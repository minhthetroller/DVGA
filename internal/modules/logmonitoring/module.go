// Package logmonitoring implements Security Logging and Monitoring Failures scenarios.
package logmonitoring

import (
	"net/http"

	"DVGA/internal/core"
	"DVGA/internal/database"
	"DVGA/internal/session"
)

type scenarioFunc func(m *LogMonitoringModule, w http.ResponseWriter, r *http.Request)

// LogMonitoringModule handles all logging and monitoring failure scenarios.
type LogMonitoringModule struct {
	difficulty core.Difficulty
	meta       core.ModuleMeta
	serve      scenarioFunc
	store      *database.Store
	sess       *session.Manager
}

func (m *LogMonitoringModule) Meta() core.ModuleMeta { return m.meta }

func (m *LogMonitoringModule) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.serve(m, w, r)
}
