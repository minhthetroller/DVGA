package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	AWSRegion          string
	ECSCluster         string
	ECRImage           string
	Domain             string
	InactivityTimeout  int
	MaxUsers           int
	TaskDefinitionARN  string
	SubnetIDs          []string
	SecurityGroupID    string
}

func loadConfig() *Config {
	timeout, _ := strconv.Atoi(getEnv("INACTIVITY_TIMEOUT_MIN", "30"))
	maxUsers, _ := strconv.Atoi(getEnv("MAX_USERS", "10"))

	return &Config{
		AWSRegion:         getEnv("AWS_REGION", "us-east-1"),
		ECSCluster:        getEnv("ECS_CLUSTER", "dvga-cluster"),
		ECRImage:          getEnv("ECR_IMAGE", ""),
		Domain:            getEnv("DOMAIN", "dvga.online"),
		InactivityTimeout: timeout,
		MaxUsers:          maxUsers,
		TaskDefinitionARN: getEnv("TASK_DEFINITION_ARN", ""),
		SubnetIDs:         strings.Split(getEnv("SUBNET_IDS", ""), ","),
		SecurityGroupID:   getEnv("SECURITY_GROUP_ID", ""),
	}
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

func main() {
	cfg := loadConfig()

	ecsClient, err := NewECSClient(cfg)
	if err != nil {
		log.Fatalf("failed to create ECS client: %v", err)
	}

	sessions := NewSessionManager()

	go NewInactivityMonitor(sessions, ecsClient, cfg.InactivityTimeout)

	h := NewHandlers(cfg, ecsClient, sessions)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", h.signupPage)
	mux.HandleFunc("POST /signup", h.signup)
	mux.HandleFunc("GET /status", h.status)
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("GET /ping/{username}", h.ping)

	addr := ":8080"
	fmt.Printf("provisioner listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
