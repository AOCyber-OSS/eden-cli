package daemon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// CertProvider supplies TLS certificates dynamically per-ClientHello.
// The TLS subsystem (TRD-02) implements this interface.
type CertProvider interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

// Proxy is an HTTP/HTTPS reverse proxy with Host-based routing.
// It routes requests from <name>.eden.test to the corresponding workspace
// backend port, with WebSocket passthrough via httputil.ReverseProxy.
type Proxy struct {
	state     *State
	certs     CertProvider
	domain    string // e.g. "eden.test"
	httpPort  int    // 80 or 9280
	httpsPort int    // 443 or 9283
	httpSrv   *http.Server
	httpsSrv  *http.Server
	listeners []net.Listener
	startTime time.Time

	// OnRequest is an optional callback for process pool integration (TRD-04).
	// Called with the workspace name before proxying. Returns the backend port
	// or an error. If nil, the proxy looks up the port from State directly.
	OnRequest func(ctx context.Context, name string) (int, error)

	// AllowLAN exposes the proxy on every interface. Off by default: anyone
	// on the network could otherwise send a *.eden.test Host header and reach
	// (and on-demand start) the developer's linked servers. Set only by the
	// explicit `eden dev daemon --lan` opt-in.
	AllowLAN bool

	// listenFn binds a listener; net.Listen unless a test replaces it.
	listenFn func(network, addr string) (net.Listener, error)
}

// NewProxy creates a new Proxy. The certs parameter may be nil, in which case
// the HTTPS server will not be started (useful for testing HTTP-only).
func NewProxy(state *State, certs CertProvider, domain string, httpPort, httpsPort int) *Proxy {
	return &Proxy{
		state:     state,
		certs:     certs,
		domain:    domain,
		httpPort:  httpPort,
		httpsPort: httpsPort,
		startTime: time.Now(),
		listenFn:  net.Listen,
	}
}

// ListenAndServe starts both the HTTP redirect server and the HTTPS proxy
// server. It returns a bind error immediately; otherwise it blocks until ctx
// is cancelled.
func (p *Proxy) ListenAndServe(ctx context.Context) error {
	if err := p.Start(); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

// Start binds the HTTP and (when certs are set) HTTPS listeners and serves
// them in the background. Call Shutdown to stop them.
func (p *Proxy) Start() error {
	// HTTP server: redirects to HTTPS (except health check).
	p.httpSrv = &http.Server{
		Handler:           http.HandlerFunc(p.handleHTTP),
		ReadHeaderTimeout: 10 * time.Second,
	}
	httpLns, err := p.listen(p.httpPort)
	if err != nil {
		return fmt.Errorf("HTTP server: %w", err)
	}
	for _, ln := range httpLns {
		p.serve(ln, "HTTP redirect server", func(l net.Listener) error { return p.httpSrv.Serve(l) })
	}

	// HTTPS server: reverse proxy with TLS.
	if p.certs != nil {
		p.httpsSrv = &http.Server{
			Handler: http.HandlerFunc(p.handleHTTPS),
			TLSConfig: &tls.Config{
				GetCertificate: p.certs.GetCertificate,
				MinVersion:     tls.VersionTLS12,
			},
			ReadHeaderTimeout: 10 * time.Second,
		}
		httpsLns, err := p.listen(p.httpsPort)
		if err != nil {
			p.closeListeners()
			return fmt.Errorf("HTTPS server: %w", err)
		}
		for _, ln := range httpsLns {
			// Empty cert/key: tls.Config.GetCertificate supplies them.
			p.serve(ln, "HTTPS proxy server", func(l net.Listener) error { return p.httpsSrv.ServeTLS(l, "", "") })
		}
	}
	return nil
}

// listen binds the listener(s) for one port: IPv4 and IPv6 loopback, or every
// interface when AllowLAN is set.
//
// macOS lets an unprivileged process bind a port below 1024 only on the
// wildcard address; 127.0.0.1:80 and 127.0.0.1:443 fail with EACCES. In that
// case listen binds the wildcard address but wraps it in loopbackOnlyListener,
// so the default stays loopback-only without needing root.
func (p *Proxy) listen(port int) ([]net.Listener, error) {
	portStr := strconv.Itoa(port)
	if p.AllowLAN {
		slog.Warn("proxy: LAN exposure enabled; linked workspaces are reachable from the network", "port", port)
		ln, err := p.listenFn("tcp", net.JoinHostPort("", portStr))
		if err != nil {
			return nil, err
		}
		return []net.Listener{ln}, nil
	}

	v4, err := p.listenFn("tcp", net.JoinHostPort("127.0.0.1", portStr))
	if errors.Is(err, syscall.EACCES) {
		ln, werr := p.listenFn("tcp", net.JoinHostPort("", portStr))
		if werr != nil {
			return nil, werr
		}
		slog.Info("proxy: loopback bind needs root on this port; serving the wildcard address restricted to loopback peers", "port", port)
		return []net.Listener{loopbackOnlyListener{ln}}, nil
	}
	if err != nil {
		return nil, err
	}
	lns := []net.Listener{v4}
	if v6, err := p.listenFn("tcp", net.JoinHostPort("::1", portStr)); err == nil {
		lns = append(lns, v6)
	} else {
		slog.Warn("proxy: IPv6 loopback unavailable, serving IPv4 loopback only", "port", port, "error", err)
	}
	return lns, nil
}

// serve records ln and serves it in the background.
func (p *Proxy) serve(ln net.Listener, what string, serveFn func(net.Listener) error) {
	p.listeners = append(p.listeners, ln)
	slog.Info(what+" starting", "addr", ln.Addr().String())
	go func() {
		if err := serveFn(ln); err != nil && err != http.ErrServerClosed {
			slog.Error(what+" stopped", "addr", ln.Addr().String(), "error", err)
		}
	}()
}

// closeListeners closes every listener bound so far (used when a later bind
// fails part-way through Start).
func (p *Proxy) closeListeners() {
	for _, ln := range p.listeners {
		_ = ln.Close()
	}
}

// Addrs returns the addresses the proxy is listening on.
func (p *Proxy) Addrs() []net.Addr {
	addrs := make([]net.Addr, 0, len(p.listeners))
	for _, ln := range p.listeners {
		addrs = append(addrs, ln.Addr())
	}
	return addrs
}

// Shutdown gracefully stops both HTTP and HTTPS servers.
func (p *Proxy) Shutdown(ctx context.Context) error {
	var firstErr error
	if p.httpSrv != nil {
		if err := p.httpSrv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("HTTP server shutdown: %w", err)
		}
	}
	if p.httpsSrv != nil {
		if err := p.httpsSrv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("HTTPS server shutdown: %w", err)
		}
	}
	return firstErr
}

// handleHTTP serves the HTTP (non-TLS) listener. It redirects all requests to
// the HTTPS equivalent, except for the /_eden/health endpoint.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Health check endpoint — available on HTTP for monitoring.
	if r.URL.Path == "/_eden/health" {
		p.serveHealth(w, r)
		return
	}

	// 301 redirect to HTTPS.
	host := r.Host
	// Strip port from host if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	target := "https://" + host
	if p.httpsPort != 443 {
		target = fmt.Sprintf("https://%s:%d", host, p.httpsPort)
	}
	target += r.URL.RequestURI()

	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// handleHTTPS is the main request handler for the HTTPS proxy server.
func (p *Proxy) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	// Health check endpoint.
	if r.URL.Path == "/_eden/health" {
		p.serveHealth(w, r)
		return
	}

	// Extract workspace name from host.
	name, err := p.extractWorkspace(r.Host)
	if err != nil {
		// Host doesn't match *.eden.test pattern.
		p.serveError(w, http.StatusBadRequest, "Invalid Host",
			fmt.Sprintf("Host %q does not match *.%s", r.Host, p.domain))
		return
	}

	// No workspace prefix — serve status dashboard.
	if name == "" {
		p.serveDashboard(w, r)
		return
	}

	// Resolve backend port.
	port, resolveErr := p.resolvePort(r.Context(), name)
	if resolveErr != nil {
		p.serveError(w, http.StatusServiceUnavailable, "Workspace Not Started",
			fmt.Sprintf("Workspace %q is not running. Link it with: eden dev link %s /path/to/app", name, name))
		return
	}
	if port == 0 {
		p.serveError(w, http.StatusNotFound, "Workspace Not Found",
			fmt.Sprintf("No workspace named %q is registered.", name))
		return
	}

	// Create reverse proxy to backend.
	target := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("127.0.0.1:%d", port),
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = r.Host // preserve original Host header
		},
		FlushInterval: -1, // stream responses (SSE, gRPC-web)
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			slog.Error("proxy backend error",
				"workspace", name,
				"target", target.String(),
				"error", err,
			)
			p.serveError(rw, http.StatusBadGateway, "Backend Unavailable",
				fmt.Sprintf("Could not reach workspace %q at port %d: %v", name, port, err))
		},
	}

	proxy.ServeHTTP(w, r)
}

// extractWorkspace parses the workspace name from a Host header value.
// For "biz.eden.test" it returns "biz". For "api.biz.eden.test" it returns
// "api.biz". For "eden.test" (no prefix) it returns "". Returns an error
// if the host doesn't end with the configured domain.
func (p *Proxy) extractWorkspace(host string) (string, error) {
	// Strip port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	host = strings.ToLower(host)
	domain := strings.ToLower(p.domain)

	// Exact match: eden.test -> dashboard.
	if host == domain {
		return "", nil
	}

	// Must end with .eden.test
	suffix := "." + domain
	if !strings.HasSuffix(host, suffix) {
		return "", fmt.Errorf("host %q does not end with %q", host, suffix)
	}

	// Extract everything before .eden.test
	name := strings.TrimSuffix(host, suffix)
	if name == "" {
		return "", fmt.Errorf("empty workspace name in host %q", host)
	}

	return name, nil
}

// resolvePort determines the backend port for a workspace. If an OnRequest
// callback is set (process pool from TRD-04), it's called first. Otherwise
// the port is looked up directly from State.
func (p *Proxy) resolvePort(ctx context.Context, name string) (int, error) {
	if p.OnRequest != nil {
		return p.OnRequest(ctx, name)
	}

	ws := p.state.Get(name)
	if ws == nil {
		return 0, fmt.Errorf("workspace %q not found", name)
	}
	if ws.Port == 0 {
		return 0, fmt.Errorf("workspace %q has no port assigned", name)
	}
	return ws.Port, nil
}

// serveHealth returns a JSON health check response.
func (p *Proxy) serveHealth(w http.ResponseWriter, _ *http.Request) {
	workspaces := p.state.All()
	uptime := time.Since(p.startTime).Truncate(time.Second)

	resp := struct {
		Status     string `json:"status"`
		Workspaces int    `json:"workspaces"`
		Uptime     string `json:"uptime"`
	}{
		Status:     "ok",
		Workspaces: len(workspaces),
		Uptime:     formatDuration(uptime),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// formatDuration formats a duration as "Xh Ym Zs".
func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// serveDashboard renders the status dashboard at eden.test (no workspace prefix).
func (p *Proxy) serveDashboard(w http.ResponseWriter, _ *http.Request) {
	workspaces := p.state.All()
	sort.Slice(workspaces, func(i, j int) bool {
		return workspaces[i].Name < workspaces[j].Name
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	dashboardTmpl.Execute(w, struct {
		Domain     string
		Workspaces []*WorkspaceState
		Uptime     string
		HTTPSPort  int
	}{
		Domain:     p.domain,
		Workspaces: workspaces,
		Uptime:     formatDuration(time.Since(p.startTime).Truncate(time.Second)),
		HTTPSPort:  p.httpsPort,
	})
}

// serveError renders an HTML error page with a list of available workspaces.
func (p *Proxy) serveError(w http.ResponseWriter, code int, title, message string) {
	workspaces := p.state.All()
	sort.Slice(workspaces, func(i, j int) bool {
		return workspaces[i].Name < workspaces[j].Name
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	errorTmpl.Execute(w, struct {
		Code       int
		Title      string
		Message    string
		Domain     string
		Workspaces []*WorkspaceState
		HTTPSPort  int
	}{
		Code:       code,
		Title:      title,
		Message:    message,
		Domain:     p.domain,
		Workspaces: workspaces,
		HTTPSPort:  p.httpsPort,
	})
}

// workspaceURL returns the full URL for a workspace, including non-standard ports.
func workspaceURL(name, domain string, httpsPort int) string {
	if httpsPort == 443 {
		return fmt.Sprintf("https://%s.%s", name, domain)
	}
	return fmt.Sprintf("https://%s.%s:%d", name, domain, httpsPort)
}

var dashboardTmpl = template.Must(template.New("dashboard").Funcs(template.FuncMap{
	"workspaceURL":   workspaceURL,
	"formatDuration": formatDuration,
	"wsUptime": func(ws *WorkspaceState) string {
		if ws.Started.IsZero() || ws.Status != "running" {
			return "-"
		}
		return formatDuration(time.Since(ws.Started).Truncate(time.Second))
	},
	"wsLastReq": func(ws *WorkspaceState) string {
		if ws.LastReq.IsZero() {
			return "-"
		}
		ago := time.Since(ws.LastReq).Truncate(time.Second)
		return formatDuration(ago) + " ago"
	},
}).Parse(`<!DOCTYPE html>
<html>
<head>
  <title>Eden Dev Server</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 960px; margin: 40px auto; padding: 0 20px; color: #333; }
    h1 { color: #1a1a2e; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #e0e0e0; }
    th { background: #f5f5f5; font-weight: 600; }
    a { color: #0066cc; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .status { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 13px; }
    .status-running { background: #d4edda; color: #155724; }
    .status-stopped { background: #f8d7da; color: #721c24; }
    .status-starting { background: #fff3cd; color: #856404; }
    .status-idle { background: #e2e3e5; color: #383d41; }
    .meta { color: #666; font-size: 14px; margin-top: 8px; }
    .pid { font-family: monospace; font-size: 13px; color: #666; }
  </style>
</head>
<body>
  <h1>Eden Dev Server</h1>
  <p class="meta">Domain: {{.Domain}} | Uptime: {{.Uptime}} | Workspaces: {{len .Workspaces}}</p>
  {{if .Workspaces}}
  <table>
    <tr><th>Workspace</th><th>Status</th><th>Port</th><th>PID</th><th>Uptime</th><th>Last Request</th><th>URL</th></tr>
    {{range .Workspaces}}
    <tr>
      <td>{{.Name}}</td>
      <td><span class="status status-{{.Status}}">{{.Status}}</span></td>
      <td>{{if .Port}}{{.Port}}{{else}}-{{end}}</td>
      <td class="pid">{{if .PID}}{{.PID}}{{else}}-{{end}}</td>
      <td>{{wsUptime .}}</td>
      <td>{{wsLastReq .}}</td>
      <td><a href="{{workspaceURL .Name $.Domain $.HTTPSPort}}">{{workspaceURL .Name $.Domain $.HTTPSPort}}</a></td>
    </tr>
    {{end}}
  </table>
  {{else}}
  <p>No workspaces registered. Link one with:</p>
  <pre>eden dev link myapp /path/to/app</pre>
  {{end}}
</body>
</html>
`))

var errorTmpl = template.Must(template.New("error").Funcs(template.FuncMap{
	"workspaceURL": workspaceURL,
}).Parse(`<!DOCTYPE html>
<html>
<head>
  <title>{{.Title}} - Eden Dev Server</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; color: #333; }
    h1 { color: #c0392b; }
    .message { background: #f8f9fa; padding: 16px; border-radius: 8px; border-left: 4px solid #c0392b; margin: 20px 0; }
    h2 { color: #1a1a2e; font-size: 18px; margin-top: 30px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #e0e0e0; }
    th { background: #f5f5f5; font-weight: 600; }
    a { color: #0066cc; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>{{.Code}} {{.Title}}</h1>
  <div class="message">{{.Message}}</div>
  {{if .Workspaces}}
  <h2>Available Workspaces</h2>
  <table>
    <tr><th>Workspace</th><th>URL</th></tr>
    {{range .Workspaces}}
    <tr>
      <td>{{.Name}}</td>
      <td><a href="{{workspaceURL .Name $.Domain $.HTTPSPort}}">{{workspaceURL .Name $.Domain $.HTTPSPort}}</a></td>
    </tr>
    {{end}}
  </table>
  {{end}}
</body>
</html>
`))

// loopbackOnlyListener accepts only connections whose peer is a loopback
// address and closes every other one before a byte is read. It guards the
// wildcard fallback in listen: off-host clients can complete a TCP handshake
// but can never send a request.
type loopbackOnlyListener struct {
	net.Listener
}

func (l loopbackOnlyListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if tcp, ok := c.RemoteAddr().(*net.TCPAddr); ok && tcp.IP.IsLoopback() {
			return c, nil
		}
		slog.Debug("proxy: refused non-loopback connection", "remote", c.RemoteAddr().String())
		_ = c.Close()
	}
}
