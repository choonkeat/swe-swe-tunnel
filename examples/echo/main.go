// Command echo is a tiny HTTP + WebSocket echo server intended for end-to-end
// testing of swe-swe-tunnel. Run on the same host as `swe-swe-tunnel` and hit
// it through the public hostname:
//
//	./echo --listen=:1977
//	./swe-swe-tunnel --server=https://tunnel.example.com --unique=test --target=127.0.0.1
//	curl https://1977.test-tunnel.example.com/healthz
//
// Routes:
//
//	GET  /          → HTML page showing what the server saw (Host, headers, etc.)
//	GET  /healthz   → "ok"
//	POST /echo      → echoes the request body
//	     /ws        → WebSocket echo (any frame in is echoed back verbatim)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/websocket"
)

func main() {
	listen := flag.String("listen", ":1977", "address to listen on")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/echo", echoHTTP)
	mux.Handle("/ws", websocket.Handler(echoWS))

	srv := &http.Server{
		Addr:              *listen,
		Handler:           logging(logger, mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("listening", "addr", *listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html><body style="font-family:sans-serif;padding:2em">
<h1>swe-swe-tunnel echo server</h1>
<p>Routes:</p>
<ul>
  <li><code>GET /healthz</code></li>
  <li><code>POST /echo</code> — echoes the request body</li>
  <li><code>/ws</code> — WebSocket echo</li>
</ul>
<h2>What this request looked like</h2>
<pre>Host:            %s
Method:          %s
URL:             %s
RemoteAddr:      %s
X-Forwarded-For: %s
X-Forwarded-Proto: %s
X-Forwarded-Host:  %s</pre>
</body></html>`,
		htmlEscape(r.Host),
		r.Method,
		htmlEscape(r.URL.String()),
		r.RemoteAddr,
		r.Header.Get("X-Forwarded-For"),
		r.Header.Get("X-Forwarded-Proto"),
		htmlEscape(r.Header.Get("X-Forwarded-Host")),
	)
}

func echoHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	_, _ = io.Copy(w, r.Body)
}

func echoWS(ws *websocket.Conn) {
	defer ws.Close()
	_, _ = io.Copy(ws, ws)
}

func logging(logger *slog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request",
			"method", r.Method,
			"host", r.Host,
			"path", r.URL.Path,
			"upgrade", r.Header.Get("Upgrade"),
		)
		h.ServeHTTP(w, r)
	})
}

func htmlEscape(s string) string {
	r := []rune(s)
	out := make([]rune, 0, len(r))
	for _, c := range r {
		switch c {
		case '<':
			out = append(out, []rune("&lt;")...)
		case '>':
			out = append(out, []rune("&gt;")...)
		case '&':
			out = append(out, []rune("&amp;")...)
		case '"':
			out = append(out, []rune("&quot;")...)
		default:
			out = append(out, c)
		}
	}
	return string(out)
}
