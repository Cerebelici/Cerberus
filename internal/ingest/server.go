package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/gr0gu/cerberus/internal/config"
	"github.com/gr0gu/cerberus/internal/detect"
	"github.com/gr0gu/cerberus/internal/model"
	"github.com/gr0gu/cerberus/internal/storage"
)

// LoopbackHost is the only address the ingest listener binds to.
const LoopbackHost = "127.0.0.1"

// Server exposes the agent telemetry API. It is deliberately separate from the UI
// transport (Wails IPC): only agent routes and /health are served, and only on loopback.
type Server struct {
	cfg        *config.Config
	store      *storage.Storage
	dispatcher *Dispatcher
	engine     *detect.Engine
	http       *http.Server
	ln         net.Listener
	startTime  time.Time
}

// NewServer wires the detection engine, dispatch pipeline and agent routes.
func NewServer(ctx context.Context, cfg *config.Config, store *storage.Storage) *Server {
	engine := detect.NewEngine(store)
	engine.Start(ctx)

	dispatcher := NewDispatcher(store, cfg.IngestShards)
	dispatcher.SetProcessor(func(events []model.NormalizedEvent) {
		_ = engine.ProcessSync(events)
	})
	dispatcher.Start(ctx)

	h := NewHandler(cfg, store, dispatcher)
	mux := http.NewServeMux()

	// Agent telemetry ingestion.
	mux.HandleFunc("POST /api/v1/agent/enroll", h.HandleEnroll)
	mux.Handle("POST /api/v1/agent/telemetry", AgentAuthMiddleware(store, http.HandlerFunc(h.HandleTelemetry)))

	// Agent inventory and revoke routes stay available locally for operators.
	mux.HandleFunc("GET /api/agents", h.HandleGetAgents)
	mux.HandleFunc("GET /api/agents/{id}", h.HandleGetAgentByID)
	mux.HandleFunc("DELETE /api/agents/{id}", h.HandleDeleteAgent)
	mux.HandleFunc("GET /api/agent-events", h.HandleGetAgentEvents)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	addr := fmt.Sprintf("%s:%d", IngestHost(cfg), cfg.IngestPort)
	return &Server{
		cfg:        cfg,
		store:      store,
		dispatcher: dispatcher,
		engine:     engine,
		startTime:  time.Now().UTC(),
		http: &http.Server{
			Addr:         addr,
			Handler:      recoveryMiddleware(loggingMiddleware(mux)),
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}
}

// IngestHost returns the configured bind address, forced to loopback. The ingest API is
// not authenticated for network use, so a non-loopback setting is refused rather than
// silently exposing telemetry intake to the LAN.
func IngestHost(cfg *config.Config) string {
	host := LoopbackHost
	if cfg != nil && cfg.IngestHost != "" {
		host = cfg.IngestHost
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		log.Printf("[Ingest] Refusing non-loopback bind %q; using %s", host, LoopbackHost)
		return LoopbackHost
	}
	return host
}

// Engine returns the detection engine fed by ingested telemetry.
func (s *Server) Engine() *detect.Engine {
	return s.engine
}

// Start binds the listener and serves requests in the background. The caller keeps
// running when the port is busy; the error is returned for logging.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return fmt.Errorf("binding ingest listener %s: %w", s.http.Addr, err)
	}
	s.ln = ln
	log.Printf("[Ingest] Agent telemetry listener on http://%s", ln.Addr().String())

	go func() {
		if serveErr := s.http.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("[Ingest] Listener stopped: %v", serveErr)
		}
	}()
	return nil
}

// Addr returns the bound address, or the configured address before Start.
func (s *Server) Addr() string {
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	return s.http.Addr
}

// Shutdown stops the listener, then the dispatcher and detection engine.
func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	if s.http != nil {
		err = s.http.Shutdown(ctx)
	}
	if s.dispatcher != nil {
		_ = s.dispatcher.Stop(ctx)
	}
	if s.engine != nil {
		_ = s.engine.Stop(ctx)
	}
	return err
}

// --- Middlewares ---

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *statusResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		if r.URL.Path == "/health" && wrapped.statusCode < http.StatusBadRequest {
			return
		}
		log.Printf("[Ingest] %s %s -> %d in %v",
			r.Method, r.URL.Path, wrapped.statusCode, time.Since(start))
	})
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[Ingest PANIC] %v", rec)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
