package brokenactest

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"DVGA/internal/core"

	"github.com/stretchr/testify/assert"
)

// setupFilesDir creates a temporary data/files directory with test files,
// then changes the working directory to that temp root for the duration of the test.
func setupFilesDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	filesDir := filepath.Join(dir, "data", "files")
	if err := os.MkdirAll(filesDir, 0750); err != nil {
		t.Fatalf("setupFilesDir: %v", err)
	}
	// Create test files matching the production data/files/ contents
	files := map[string]string{
		"config.txt": "server_host=localhost\nserver_port=4280",
		"notes.txt":  "Meeting notes: deploy on Friday",
		"readme.txt": "Welcome to DVGA",
	}
	for name, content := range files {
		path := filepath.Join(filesDir, name)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("setupFilesDir: write %s: %v", name, err)
		}
	}

	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("setupFilesDir: getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("setupFilesDir: chdir: %v", err)
	}
	t.Cleanup(func() { os.Chdir(original) })
}

// TestPathTraversal_Easy verifies directory traversal is fully exploitable.
func TestPathTraversal_Easy(t *testing.T) {
	setupFilesDir(t)
	app := newTestApp(t)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("valid filename returns file contents", func(t *testing.T) {
		w := doModuleRequest(t, app, "path-traversal", http.MethodGet,
			"/?file=config.txt", nil, cookie)
		assert.Contains(t, w.Body.String(), "server_host")
	})

	t.Run("dot-dot-slash traversal reads file outside base dir", func(t *testing.T) {
		// Create a sentinel file in the temp root (two levels up from data/files)
		dir := t.TempDir()
		sentinelPath := filepath.Join(dir, "sentinel.txt")
		os.WriteFile(sentinelPath, []byte("TRAVERSAL_SUCCESS"), 0600)

		// Change to dir so ./data/files is relative
		os.MkdirAll(filepath.Join(dir, "data", "files"), 0750)
		os.WriteFile(filepath.Join(dir, "data", "files", "dummy.txt"), []byte("dummy"), 0600)
		original, _ := os.Getwd()
		os.Chdir(dir)
		t.Cleanup(func() { os.Chdir(original) })

		app2 := newTestApp(t)
		token2 := app2.mustLogin(adminUsername, adminPassword)
		// ../../sentinel.txt goes: data/files → data → root → sentinel.txt
		w := doModuleRequest(t, app2, "path-traversal", http.MethodGet,
			"/?file=../../sentinel.txt", nil, app2.sessionCookie(token2))
		assert.Contains(t, w.Body.String(), "TRAVERSAL_SUCCESS")
	})

	t.Run("nonexistent file returns error", func(t *testing.T) {
		w := doModuleRequest(t, app, "path-traversal", http.MethodGet,
			"/?file=doesnotexist.txt", nil, cookie)
		assert.Contains(t, w.Body.String(), "not found")
	})
}

// TestPathTraversal_Medium verifies ../ is stripped but ....// bypass works.
func TestPathTraversal_Medium(t *testing.T) {
	dir := t.TempDir()
	filesDir := filepath.Join(dir, "data", "files")
	os.MkdirAll(filesDir, 0750)
	os.WriteFile(filepath.Join(filesDir, "config.txt"), []byte("server_host=localhost"), 0600)

	// Sentinel file one level up from data/files (i.e., in data/)
	// ....// bypass: "....//escape.txt" → after removing "../": "../escape.txt"
	// path becomes ./data/files/../escape.txt = ./data/escape.txt
	sentinelPath := filepath.Join(dir, "data", "escape.txt")
	os.WriteFile(sentinelPath, []byte("ESCAPED_MEDIUM"), 0600)

	original, _ := os.Getwd()
	os.Chdir(dir)
	t.Cleanup(func() { os.Chdir(original) })

	app := newTestApp(t)
	app.setDifficulty(core.Medium)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("valid file still works", func(t *testing.T) {
		w := doModuleRequest(t, app, "path-traversal", http.MethodGet,
			"/?file=config.txt", nil, cookie)
		assert.Contains(t, w.Body.String(), "server_host")
	})

	t.Run("simple ../ stripped — traversal blocked", func(t *testing.T) {
		w := doModuleRequest(t, app, "path-traversal", http.MethodGet,
			"/?file=../escape.txt", nil, cookie)
		// After stripping ../: becomes "escape.txt" which doesn't exist in files/
		assert.Contains(t, w.Body.String(), "not found")
	})

	t.Run("....// double-dot bypass evades the strip", func(t *testing.T) {
		// ....// → after removing ../: becomes ../  → traverses up
		w := doModuleRequest(t, app, "path-traversal", http.MethodGet,
			"/?file=....//escape.txt", nil, cookie)
		assert.Contains(t, w.Body.String(), "ESCAPED_MEDIUM")
	})
}

// TestPathTraversal_Hard verifies filepath.Clean + HasPrefix blocks all traversal.
func TestPathTraversal_Hard(t *testing.T) {
	dir := t.TempDir()
	filesDir := filepath.Join(dir, "data", "files")
	os.MkdirAll(filesDir, 0750)
	os.WriteFile(filepath.Join(filesDir, "config.txt"), []byte("server_host=localhost"), 0600)
	os.WriteFile(filepath.Join(dir, "escape.txt"), []byte("ESCAPED_HARD"), 0600)

	original, _ := os.Getwd()
	os.Chdir(dir)
	t.Cleanup(func() { os.Chdir(original) })

	app := newTestApp(t)
	app.setDifficulty(core.Hard)
	token := app.mustLogin(adminUsername, adminPassword)
	cookie := app.sessionCookie(token)

	t.Run("valid filename within base dir works", func(t *testing.T) {
		w := doModuleRequest(t, app, "path-traversal", http.MethodGet,
			"/?file=config.txt", nil, cookie)
		assert.Contains(t, w.Body.String(), "server_host")
	})

	t.Run("../ traversal blocked", func(t *testing.T) {
		w := doModuleRequest(t, app, "path-traversal", http.MethodGet,
			"/?file=../escape.txt", nil, cookie)
		assert.Contains(t, w.Body.String(), "not found")
		assert.NotContains(t, w.Body.String(), "ESCAPED_HARD")
	})

	t.Run("....// bypass blocked by filepath.Clean", func(t *testing.T) {
		w := doModuleRequest(t, app, "path-traversal", http.MethodGet,
			"/?file=....//escape.txt", nil, cookie)
		assert.Contains(t, w.Body.String(), "not found")
		assert.NotContains(t, w.Body.String(), "ESCAPED_HARD")
	})

	t.Run("absolute path blocked", func(t *testing.T) {
		w := doModuleRequest(t, app, "path-traversal", http.MethodGet,
			"/?file=/etc/passwd", nil, cookie)
		assert.Contains(t, w.Body.String(), "not found")
	})
}
