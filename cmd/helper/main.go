package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

const defaultSocketPath = "/var/run/com.cerberus.helper.sock"

func main() {
	log.Println("[Helper] Starting Cerberus Privileged Root Helper daemon...")

	sockPath := defaultSocketPath
	if envSock := os.Getenv("CERBERUS_HELPER_SOCK"); envSock != "" {
		sockPath = envSock
	}

	executor := NewRootExecutor()
	server := NewIPCServer(sockPath, executor)

	if err := server.Start(); err != nil {
		log.Fatalf("[Helper] Failed to start IPC server: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("[Helper] Received signal %v, shutting down...", sig)
	server.Stop()
	log.Println("[Helper] Helper daemon stopped cleanly.")
}
