package main

import (
	"log"
	"sync"
	"time"
)

type UserSession struct {
	Username     string    `json:"username"`
	TaskARN      string    `json:"task_arn"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]UserSession
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]UserSession),
	}
}

func (s *SessionManager) Add(username, taskArn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.sessions[username] = UserSession{
		Username:     username,
		TaskARN:      taskArn,
		CreatedAt:    now,
		LastActivity: now,
	}
}

func (s *SessionManager) Remove(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, username)
}

func (s *SessionManager) Get(username string) (UserSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[username]
	return sess, ok
}

func (s *SessionManager) GetAll() []UserSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]UserSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		result = append(result, sess)
	}
	return result
}

func (s *SessionManager) Ping(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[username]; ok {
		sess.LastActivity = time.Now()
		s.sessions[username] = sess
	}
}

func (s *SessionManager) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func NewInactivityMonitor(sessions *SessionManager, ecsClient *ECSClient, timeoutMin int) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		allSessions := sessions.GetAll()
		for _, sess := range allSessions {
			if time.Since(sess.LastActivity) > time.Duration(timeoutMin)*time.Minute {
				log.Printf("stopping inactive task for user %s (idle %v)", sess.Username, time.Since(sess.LastActivity))
				if err := ecsClient.StopTask(sess.TaskARN); err != nil {
					log.Printf("failed to stop task for user %s: %v", sess.Username, err)
					continue
				}
				sessions.Remove(sess.Username)
			}
		}
	}
}
