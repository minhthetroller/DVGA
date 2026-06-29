package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"regexp"
)

var usernameRegex = regexp.MustCompile(`^[a-z0-9]{3,20}$`)

type Handlers struct {
	cfg      *Config
	ecs      *ECSClient
	sessions *SessionManager
	dynamic  *DynamicConfig
	tracker  *LaunchTracker
	tmpl     *template.Template
}

func NewHandlers(cfg *Config, ecsClient *ECSClient, sessions *SessionManager, dynamic *DynamicConfig, tracker *LaunchTracker) *Handlers {
	tmpl := template.Must(template.ParseFiles("templates/signup.html"))
	return &Handlers{
		cfg:      cfg,
		ecs:      ecsClient,
		sessions: sessions,
		dynamic:  dynamic,
		tracker:  tracker,
		tmpl:     tmpl,
	}
}

type signupData struct {
	Error     string
	Domain    string
	Launching bool
	Username  string
}

func (h *Handlers) signupPage(w http.ResponseWriter, r *http.Request) {
	h.tmpl.Execute(w, signupData{Domain: h.cfg.Domain})
}

func (h *Handlers) signup(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	if !usernameRegex.MatchString(username) {
		h.tmpl.Execute(w, signupData{
			Error:  "Username must be 3-20 lowercase alphanumeric characters",
			Domain: h.cfg.Domain,
		})
		return
	}

	if _, exists := h.sessions.Get(username); exists {
		h.tmpl.Execute(w, signupData{
			Error:  "Username already active",
			Domain: h.cfg.Domain,
		})
		return
	}

	if _, exists := h.tracker.Get(username); exists {
		h.tmpl.Execute(w, signupData{
			Error:  "Username already launching",
			Domain: h.cfg.Domain,
		})
		return
	}

	if h.sessions.Count() >= h.cfg.MaxUsers {
		h.tmpl.Execute(w, signupData{
			Error:  "Maximum number of active instances reached",
			Domain: h.cfg.Domain,
		})
		return
	}

	h.tracker.Set(username, LaunchState{Stage: StageSubmitting, Percent: 10, Message: "Submitting request..."})

	go h.launchInstance(username)

	w.WriteHeader(http.StatusAccepted)
	h.tmpl.Execute(w, signupData{
		Domain:    h.cfg.Domain,
		Launching: true,
		Username:  username,
	})
}

// launchInstance runs the full Fargate launch lifecycle in the
// background, updating the LaunchTracker at each stage. Called from
// signup via `go h.launchInstance(username)`.
func (h *Handlers) launchInstance(username string) {
	taskArn, err := h.ecs.RunTask(username)
	if err != nil {
		log.Printf("failed to run task for %s: %v", username, err)
		h.tracker.Set(username, LaunchState{
			Stage:   StageFailed,
			Message: "Failed to launch instance",
			Error:   err.Error(),
		})
		return
	}

	if err := h.ecs.RunTaskProgress(taskArn, username, h.tracker); err != nil {
		log.Printf("task for %s did not reach RUNNING: %v", username, err)
		h.ecs.StopTask(taskArn)
		h.tracker.Set(username, LaunchState{
			Stage:   StageFailed,
			Message: "Instance launch timed out",
			Error:   err.Error(),
		})
		return
	}

	h.tracker.Set(username, LaunchState{Stage: StageRouting, Percent: 85, Message: "Configuring routing..."})

	ip, err := h.ecs.GetTaskIP(taskArn)
	if err != nil {
		log.Printf("could not get task IP for %s: %v", username, err)
		h.ecs.StopTask(taskArn)
		h.tracker.Set(username, LaunchState{
			Stage:   StageFailed,
			Message: "Instance launch timed out",
			Error:   err.Error(),
		})
		return
	}

	h.dynamic.Add(username, ip)
	h.sessions.Add(username, taskArn)
	h.tracker.Set(username, LaunchState{Stage: StageReady, Percent: 100, Message: "Redirecting..."})
}

func (h *Handlers) launchStatus(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	state, ok := h.tracker.Get(username)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state)
}

func (h *Handlers) status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.sessions.GetAll())
}

func (h *Handlers) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (h *Handlers) ping(w http.ResponseWriter, r *http.Request) {
	username := r.PathValue("username")
	h.sessions.Ping(username)
	w.WriteHeader(http.StatusOK)
}
