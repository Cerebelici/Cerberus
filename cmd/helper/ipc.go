package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"
)

// JSONRPCRequest represents an incoming IPC request.
type JSONRPCRequest struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// JSONRPCResponse represents an IPC response.
type JSONRPCResponse struct {
	ID     string `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// ExecuteParams defines parameters for privileged process execution.
type ExecuteParams struct {
	Binary string   `json:"binary"`
	Args   []string `json:"args"`
	Env    []string `json:"env,omitempty"`
}

// IPCServer manages the Unix Domain Socket listener.
type IPCServer struct {
	socketPath string
	listener   net.Listener
	executor   *RootExecutor
	mu         sync.Mutex
	stopCh     chan struct{}
}

// NewIPCServer creates an IPC server instance.
func NewIPCServer(socketPath string, executor *RootExecutor) *IPCServer {
	return &IPCServer{
		socketPath: socketPath,
		executor:   executor,
		stopCh:     make(chan struct{}),
	}
}

// Start binds to the socket and begins serving.
func (s *IPCServer) Start() error {
	_ = os.Remove(s.socketPath)

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("binding socket %s: %w", s.socketPath, err)
	}

	// The desktop app runs as an admin user, not as root. On macOS the socket is owned
	// by root:admin with mode 0660, so administrators can connect without granting every
	// local account access. Non-macOS helpers are not used by the desktop app.
	if grp, err := user.LookupGroup("admin"); err == nil {
		if gid, convErr := strconv.Atoi(grp.Gid); convErr == nil {
			_ = os.Chown(s.socketPath, 0, gid)
		}
	}
	if err := os.Chmod(s.socketPath, 0660); err != nil {
		_ = l.Close()
		return fmt.Errorf("setting socket permissions: %w", err)
	}

	s.listener = l
	log.Printf("[Helper] Privileged helper IPC listening at %s", s.socketPath)

	go s.serve()
	return nil
}

// Stop shuts down the IPC server and removes the socket file.
func (s *IPCServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	close(s.stopCh)
	if s.listener != nil {
		_ = s.listener.Close()
	}
	_ = os.Remove(s.socketPath)
}

func (s *IPCServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				log.Printf("[Helper] Accept error: %v", err)
				return
			}
		}

		go s.handleConnection(conn)
	}
}

func (s *IPCServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Verify peer credentials
	uid, err := VerifyPeerCredentials(conn)
	if err != nil {
		log.Printf("[Helper] Rejected connection: peer verification failed: %v", err)
		return
	}
	log.Printf("[Helper] Accepted client connection from UID %d", uid)

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[Helper] Connection read error: %v", err)
			}
			return
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(conn, "", fmt.Sprintf("invalid json-rpc request: %v", err))
			continue
		}

		s.dispatch(conn, req)
	}
}

func (s *IPCServer) dispatch(conn net.Conn, req JSONRPCRequest) {
	switch req.Method {
	case "Ping":
		s.sendResult(conn, req.ID, map[string]string{
			"status":  "ok",
			"version": "1.0.0",
		})

	case "Execute":
		var params ExecuteParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.sendError(conn, req.ID, "invalid execute parameters")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		out, err := s.executor.Execute(ctx, params.Binary, params.Env, params.Args...)
		if err != nil {
			s.sendError(conn, req.ID, fmt.Sprintf("%v (output: %s)", err, string(out)))
			return
		}

		s.sendResult(conn, req.ID, map[string]string{
			"output": string(out),
		})

	default:
		s.sendError(conn, req.ID, fmt.Sprintf("unknown method: %s", req.Method))
	}
}

func (s *IPCServer) sendResult(conn net.Conn, id string, result any) {
	resp := JSONRPCResponse{
		ID:     id,
		Result: result,
	}
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

func (s *IPCServer) sendError(conn net.Conn, id string, errMsg string) {
	resp := JSONRPCResponse{
		ID:    id,
		Error: errMsg,
	}
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	_, _ = conn.Write(data)
}
