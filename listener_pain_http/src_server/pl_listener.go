package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// startHTTP parses the uploaded C2 profile, registers routes, and starts the server.
func (l *HTTPListener) startHTTP() error {
	// --- decode and parse the C2 profile ---
	if l.Config.ProfileContent == "" {
		return fmt.Errorf("[Pain Listener] no profile uploaded - cannot start")
	}

	profileBytes, err := base64.StdEncoding.DecodeString(l.Config.ProfileContent)
	if err != nil {
		return fmt.Errorf("[Pain Listener] profile base64 decode failed: %w", err)
	}

	callbacks, err := parseProfile(l, string(profileBytes))
	if err != nil {
		return fmt.Errorf("[Pain Listener] profile parse failed: %w", err)
	}
	l.Config.Callbacks = callbacks
	fmt.Printf("[Pain Listener] loaded %d callback(s) from profile\n", len(callbacks))

	// --- build the HTTP mux ---
	// "/" in Go's ServeMux is a catch-all - every path hits dispatch.
	mux := http.NewServeMux()
	mux.HandleFunc("/", l.dispatch)

	l.server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", l.Config.HostBind, l.Config.PortBind),
		Handler: mux,
	}

	scheme := "http"
	errCh := make(chan error, 1)

	if l.Config.Ssl {
		scheme = "https"
		certPath, keyPath, err := l.resolveSSL()
		if err != nil {
			return fmt.Errorf("[Pain Listener] TLS setup failed: %w", err)
		}
		go func() {
			if e := l.server.ListenAndServeTLS(certPath, keyPath); e != nil && e != http.ErrServerClosed {
				errCh <- e
			} else {
				errCh <- nil
			}
		}()
	} else {
		go func() {
			if e := l.server.ListenAndServe(); e != nil && e != http.ErrServerClosed {
				errCh <- e
			} else {
				errCh <- nil
			}
		}()
	}

	// 500 ms window: fail fast if the bind fails, otherwise assume we're up
	select {
	case e := <-errCh:
		return fmt.Errorf("[Pain Listener] bind failed: %w", e)
	case <-time.After(500 * time.Millisecond):
	}

	fmt.Printf("[Pain Listener] listening on %s://%s:%d\n", scheme, l.Config.HostBind, l.Config.PortBind)
	return nil
}

// dispatch is the single entry point for every incoming request.
func (l *HTTPListener) dispatch(w http.ResponseWriter, r *http.Request) {
	reqPath   := r.URL.Path
	reqMethod := r.Method
	reqUA     := r.Header.Get("User-Agent")

	// 1. Block by User-Agent (glob patterns, one per line, e.g. "curl*" "wget*")
	if blocked := l.isBlockedUA(reqUA); blocked {
		fmt.Printf("[Pain Listener] blocked UA: %s\n", reqUA)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 2. Resolve the client host (honouring X-Forwarded-Host and trusted hosts list)
	clientHost := l.resolveHost(r)

	// 3. Find the matching callback by host
	cb := l.findCallback(clientHost)
	if cb == nil {
		l.reject(w, nil)
		return
	}

	// 4. Validate User-Agent against the callback's expected value
	if cb.UserAgent != "" && reqUA != cb.UserAgent {
		fmt.Printf("[Pain Listener] UA mismatch - got=%q want=%q\n", reqUA, cb.UserAgent)
		l.reject(w, cb.SrvError)
		return
	}

	// 5. Find the HTTPMethod + URIConfig for this path + verb
	hm, uriCfg := l.findURIConfig(cb, reqPath, reqMethod)
	if uriCfg == nil {
		fmt.Printf("[Pain Listener] no route for %s %s\n", reqMethod, reqPath)
		l.reject(w, cb.SrvError)
		return
	}

	// 6. Validate required client headers declared in the profile
	for hdr := range hm.ClientHeaders {
		if r.Header.Get(hdr) == "" {
			fmt.Printf("[Pain Listener] missing required header: %s\n", hdr)
			l.reject(w, cb.SrvError)
			return
		}
	}

	// 7. Read and decode the agent's data from the request
	raw, err := readClientData(r, uriCfg.ClientOutput)
	if err != nil || len(raw) < 36 {
		fmt.Printf("[Pain Listener] bad client data: %v (len=%d)\n", err, len(raw))
		l.reject(w, cb.SrvError)
		return
	}

	// Pain protocol: first 36 bytes = agent UUID, rest = encoded payload
	uid     := raw[:36]
	payload := raw[36:]

	externalIP := r.RemoteAddr
	if host, _, e := net.SplitHostPort(r.RemoteAddr); e == nil {
		externalIP = host
	}

	agentId, exists := ModuleObject.ts.TsAgentIdByUID(uid)

	if !exists {
		if len(payload) == 0 {
			// stale poll after a server restart - agent will re-check-in next cycle
			applyServerHeaders(w, hm)
			w.WriteHeader(http.StatusOK)
			return
		}
		agentData, err := ModuleObject.ts.TsAgentCreate(
			"deadbeef", uid, payload, l.Name, externalIP, true,
		)
		if err != nil {
			if retryId, found := ModuleObject.ts.TsAgentIdByUID(uid); found {
				agentId = retryId
			} else {
				fmt.Printf("[Pain Listener] TsAgentCreate error: %v\n", err)
				l.reject(w, cb.SrvError)
				return
			}
		} else {
			agentId = agentData.Id
		}
	} else if len(payload) > 0 {
		_ = ModuleObject.ts.TsAgentProcessData(agentId, payload)
	}

	_ = ModuleObject.ts.TsAgentSetTick(agentId, l.Name)

	// 8. Fetch pending tasks and encode the response per the profile
	tasks, _, err := ModuleObject.ts.TsAgentGetHostedAll(agentId, 4*1024*1024)

	applyServerHeaders(w, hm)

	if err != nil || len(tasks) == 0 {
		writeResponse(w, hm.EmptyResponse, uriCfg.ServerOutput)
		return
	}

	encoded := encodeData(tasks, uriCfg.ServerOutput)
	writeResponse(w, encoded, uriCfg.ServerOutput)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// isBlockedUA returns true when the User-Agent matches any configured block pattern.
func (l *HTTPListener) isBlockedUA(ua string) bool {
	if l.Config.BlockUserAgents == "" {
		return false
	}
	for _, pattern := range strings.Split(l.Config.BlockUserAgents, "\n") {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if matchGlob(pattern, ua) {
			return true
		}
	}
	return false
}

// resolveHost picks the client address to use for callback matching.
// Respects TrustXForwardedHost and AdditionalTrustedHosts.
func (l *HTTPListener) resolveHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// X-Forwarded-Host: use it and skip further matching
	if l.Config.TrustXForwardedHost {
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			if h, _, err := net.SplitHostPort(xfh); err == nil {
				xfh = h
			}
			return xfh
		}
	}

	// Additional Trusted Hosts: if matched, host is accepted as-is
	if l.Config.AdditionalTrustedHosts != "" {
		for _, trusted := range strings.Split(l.Config.AdditionalTrustedHosts, "\n") {
			if strings.EqualFold(strings.TrimSpace(trusted), host) {
				return host
			}
		}
	}

	return host
}

// findCallback scans all callbacks for one whose Hosts list contains clientHost.
// Falls back to Callbacks[0] when the host list is exhausted (trusted host path).
func (l *HTTPListener) findCallback(clientHost string) *Callback {
	for i := range l.Config.Callbacks {
		cb := &l.Config.Callbacks[i]
		for _, h := range cb.Hosts {
			if strings.EqualFold(h, clientHost) {
				return cb
			}
		}
	}
	if len(l.Config.Callbacks) > 0 {
		return &l.Config.Callbacks[0]
	}
	return nil
}

// findURIConfig returns the HTTPMethod and URIConfig for a given path + verb.
func (l *HTTPListener) findURIConfig(cb *Callback, path, method string) (*HTTPMethod, *URIConfig) {
	var hm *HTTPMethod
	switch method {
	case "GET":
		hm = cb.Get
	case "POST":
		hm = cb.Post
	}
	if hm == nil {
		return nil, nil
	}
	cfg, ok := hm.URI[path]
	if !ok {
		return nil, nil
	}
	return hm, &cfg
}

// reject sends the profile's server_error page, or a plain 400 if none is configured.
func (l *HTTPListener) reject(w http.ResponseWriter, se *ServerError) {
	if se != nil {
		for k, v := range se.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(se.Status)
		w.Write([]byte(se.Response))
		return
	}
	http.Error(w, "Bad Request", http.StatusBadRequest)
}

// readClientData extracts and decodes the raw payload from the request.
func readClientData(r *http.Request, out *OutputConfig) ([]byte, error) {
	if out == nil {
		body, err := io.ReadAll(r.Body)
		return body, err
	}

	var raw []byte
	switch {
	case out.Header != "":
		v := strings.ReplaceAll(r.Header.Get(out.Header), " ", "+")
		if v == "" {
			return nil, fmt.Errorf("header %q not found", out.Header)
		}
		raw = []byte(v)

	case out.Cookie != "":
		c, err := r.Cookie(out.Cookie)
		if err != nil {
			return nil, fmt.Errorf("cookie %q not found", out.Cookie)
		}
		raw = []byte(c.Value)

	case out.Parameter != "":
		v := r.URL.Query().Get(out.Parameter)
		if v == "" {
			return nil, fmt.Errorf("param %q not found", out.Parameter)
		}
		raw = []byte(v)

	default:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		raw = body
	}

	// strip prepend / append wrappers that the agent added
	if out.Prepend != "" {
		if !strings.HasPrefix(string(raw), out.Prepend) {
			return nil, fmt.Errorf("prepend %q not found in data", out.Prepend)
		}
		raw = raw[len(out.Prepend):]
	}
	if out.Append != "" {
		if !strings.HasSuffix(string(raw), out.Append) {
			return nil, fmt.Errorf("append %q not found in data", out.Append)
		}
		raw = raw[:len(raw)-len(out.Append)]
	}

	return decodeFormat(raw, out.Format), nil
}

// decodeFormat reverses the encoding specified in the profile.
func decodeFormat(data []byte, format string) []byte {
	switch format {
	case "base64":
		dec, err := base64.StdEncoding.DecodeString(string(data))
		if err == nil {
			return dec
		}
	case "base64url":
		dec, err := base64.URLEncoding.DecodeString(string(data))
		if err == nil {
			return dec
		}
	case "base32":
		dec, err := base32.StdEncoding.DecodeString(string(data))
		if err == nil {
			return dec
		}
	case "hex":
		dec, err := hex.DecodeString(string(data))
		if err == nil {
			return dec
		}
	}
	return data // "raw" or decode failure → return as-is
}

// encodeData applies the profile's output format to the response payload.
func encodeData(data []byte, out *OutputConfig) []byte {
	if out == nil {
		return data
	}
	switch out.Format {
	case "base64":
		return []byte(base64.StdEncoding.EncodeToString(data))
	case "base64url":
		return []byte(base64.URLEncoding.EncodeToString(data))
	case "base32":
		return []byte(base32.StdEncoding.EncodeToString(data))
	case "hex":
		return []byte(hex.EncodeToString(data))
	}
	return data
}

// writeResponse puts the payload in the right place according to the server OutputConfig.
func writeResponse(w http.ResponseWriter, data []byte, out *OutputConfig) {
	w.WriteHeader(http.StatusOK)

	if out == nil || (out.Header == "" && out.Cookie == "" && out.Parameter == "") {
		w.Write(data)
		return
	}

	switch {
	case out.Header != "":
		w.Header().Set(out.Header, string(data))
		if out.Body != "" {
			w.Write([]byte(out.Body))
		}
	case out.Cookie != "":
		w.Header().Set("Set-Cookie", fmt.Sprintf("%s=%s", out.Cookie, string(data)))
		if out.Body != "" {
			w.Write([]byte(out.Body))
		}
	default:
		w.Write(data)
	}
}

// applyServerHeaders writes the profile's static server headers onto the response.
func applyServerHeaders(w http.ResponseWriter, hm *HTTPMethod) {
	if hm == nil {
		return
	}
	for k, v := range hm.ServerHeaders {
		w.Header().Set(k, v)
	}
}

// matchGlob does simple wildcard matching using filepath.Match semantics.
// Supports * (any sequence) and ? (any single character).
func matchGlob(pattern, s string) bool {
	matched, err := filepath.Match(pattern, s)
	return err == nil && matched
}

// resolveSSL returns (certPath, keyPath) for TLS.
// Uses operator-uploaded bytes when present, otherwise auto-generates a self-signed cert.
func (l *HTTPListener) resolveSSL() (string, string, error) {
	if len(l.Config.SslCert) > 0 && len(l.Config.SslKey) > 0 {
		certPath := filepath.Join(ListenerDataDir, l.Name+".crt")
		keyPath  := filepath.Join(ListenerDataDir, l.Name+".key")
		if err := os.WriteFile(certPath, l.Config.SslCert, 0600); err != nil {
			return "", "", err
		}
		if err := os.WriteFile(keyPath, l.Config.SslKey, 0600); err != nil {
			return "", "", err
		}
		return certPath, keyPath, nil
	}
	return ensureCert("", "", ListenerDataDir, l.Name)
}
