package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"DVGA/internal/app"
)

func main() {
	a, err := app.New(
		"./data/dvga.db",
		"./internal/ui/templates",
		"./internal/ui/static",
	)
	if err != nil {
		log.Fatal(err)
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- a.ListenAndServe(":4280")
	}()

	// Wait for interrupt or server error
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		log.Println("Shutting down...")
	case err := <-errCh:
		log.Fatal(err)
	}

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.Server.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}
	a.Sessions.Stop()
	log.Println("Server stopped")
}
