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
	tmpl     *template.Template
}

func NewHandlers(cfg *Config, ecsClient *ECSClient, sessions *SessionManager, dynamic *DynamicConfig) *Handlers {
	tmpl := template.Must(template.ParseFiles("templates/signup.html"))
	return &Handlers{
		cfg:      cfg,
		ecs:      ecsClient,
		sessions: sessions,
		dynamic:  dynamic,
		tmpl:     tmpl,
	}
}

type signupData struct {
	Error  string
	Domain string
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

	if h.sessions.Count() >= h.cfg.MaxUsers {
		h.tmpl.Execute(w, signupData{
			Error:  "Maximum number of active instances reached",
			Domain: h.cfg.Domain,
		})
		return
	}

	taskArn, err := h.ecs.RunTask(username)
	if err != nil {
		log.Printf("failed to run task for %s: %v", username, err)
		h.tmpl.Execute(w, signupData{
			Error:  "Failed to launch instance",
			Domain: h.cfg.Domain,
		})
		return
	}

	if err := h.ecs.WaitForRunning(taskArn); err != nil {
		log.Printf("task for %s did not reach RUNNING: %v", username, err)
		h.ecs.StopTask(taskArn)
		h.tmpl.Execute(w, signupData{
			Error:  "Instance launch timed out",
			Domain: h.cfg.Domain,
		})
		return
	}

	ip, err := h.ecs.GetTaskIP(taskArn)
	if err != nil {
		log.Printf("could not get task IP for %s: %v", username, err)
		h.ecs.StopTask(taskArn)
		h.tmpl.Execute(w, signupData{
			Error:  "Instance launch timed out",
			Domain: h.cfg.Domain,
		})
		return
	}

	h.dynamic.Add(username, ip)
	h.sessions.Add(username, taskArn)
	http.Redirect(w, r, "https://"+username+"."+h.cfg.Domain, http.StatusFound)
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
