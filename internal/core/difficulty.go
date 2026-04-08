package core

import (
	"strings"
	"sync"
)

type Difficulty int

const (
	Easy Difficulty = iota
	Medium
	Hard
)

func (d Difficulty) String() string {
	switch d {
	case Easy:
		return "Easy"
	case Medium:
		return "Medium"
	case Hard:
		return "Hard"
	default:
		return "Unknown"
	}
}

func ParseDifficulty(s string) Difficulty {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "medium":
		return Medium
	case "hard":
		return Hard
	default:
		return Easy
	}
}

// SafeDifficulty is a thread-safe wrapper around a Difficulty value.
type SafeDifficulty struct {
	mu    sync.RWMutex
	value Difficulty
}

func NewSafeDifficulty(d Difficulty) *SafeDifficulty {
	return &SafeDifficulty{value: d}
}

func (sd *SafeDifficulty) Get() Difficulty {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.value
}

func (sd *SafeDifficulty) Set(d Difficulty) {
	sd.mu.Lock()
	defer sd.mu.Unlock()
	sd.value = d
}
