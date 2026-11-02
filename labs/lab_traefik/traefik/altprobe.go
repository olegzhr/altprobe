// Package traefik_altprobe implements a Traefik OSS middleware without external dependencies.
package traefik_altprobe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	RedisAddress    string
	RedisKey        string
	HostName        string
	GatewayOriginID string
	MaxBodySize     int
	TimeoutMS       int
	QueueSize       int
	Credentials     map[string]string
}

func CreateConfig() *Config {
	return &Config{RedisAddress: "redis:6379", RedisKey: "log_proxy", HostName: "traefik", MaxBodySize: 5000, TimeoutMS: 2000, QueueSize: 256}
}

type middleware struct {
	next   http.Handler
	config Config
	client *http.Client
	queue  chan []byte
}

func New(ctx context.Context, next http.Handler, c *Config, name string) (http.Handler, error) {
	if c.MaxBodySize < 1 || c.MaxBodySize > 32768 || c.TimeoutMS < 1 || c.QueueSize < 1 || c.QueueSize > 65536 {
		return nil, fmt.Errorf("invalid Altprobe body, timeout or queue limits")
	}
	config := *c
	if config.GatewayOriginID == "" {
		host, err := os.Hostname()
		if err != nil || host == "" {
			return nil, fmt.Errorf("gateway origin requires hostname or GatewayOriginID")
		}
		config.GatewayOriginID = "traefik:" + host + ":" + config.HostName + ":" + name
	}
	if len(config.GatewayOriginID) > 255 {
		return nil, fmt.Errorf("gateway origin exceeds 255 bytes")
	}
	config.Credentials = make(map[string]string)
	for k, v := range c.Credentials {
		config.Credentials[k] = v
	}
	m := &middleware{next: next, config: config, client: &http.Client{Timeout: time.Duration(c.TimeoutMS) * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, queue: make(chan []byte, c.QueueSize)}
	go m.deliver(ctx)
	return m, nil
}

type capture struct {
	data  []byte
	total int
	limit int
}

func (c *capture) Write(p []byte) (int, error) {
	c.total += len(p)
	n := c.limit - len(c.data)
	if n > len(p) {
		n = len(p)
	}
	if n > 0 {
		c.data = append(c.data, p[:n]...)
	}
	return len(p), nil
}

type captureReader struct {
	io.Reader
	closer io.Closer
}

func (r *captureReader) Close() error { return r.closer.Close() }

type responseCapture struct {
	http.ResponseWriter
	body   capture
	status int
}

func (w *responseCapture) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != 101 {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	if w.status == 0 {
		w.status = code
		w.ResponseWriter.WriteHeader(code)
	}
}
func (w *responseCapture) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(p)
	w.body.Write(p[:n])
	// Yaegi's ResponseWriter bridge can hide Flusher from the compiled proxy.
	// Flush SSE writes here as well, so the proxy need not discover that interface.
	if strings.HasPrefix(w.Header().Get("Content-Type"), "text/event-stream") {
		w.Flush()
	}
	return n, err
}
func (w *responseCapture) Flush() {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *responseCapture) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *responseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijack unsupported")
	}
	w.status = 101
	return h.Hijack()
}

func clean(h http.Header) http.Header {
	out := h.Clone()
	for _, k := range []string{"Authorization", "Proxy-Authorization", "Apikey", "Cookie", "Set-Cookie"} {
		if _, ok := out[http.CanonicalHeaderKey(k)]; ok {
			out.Set(k, "[REDACTED]")
		}
	}
	return out
}
func remoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	return addr
}
func identifier() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprint(time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}


func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	originalURI := r.URL.RequestURI()
	originalMethod := r.Method
	headers := r.Header.Clone()
	subject := ""
	if values := r.Header.Values("Apikey"); len(values) == 1 {
		subject = m.config.Credentials[values[0]]
	}
	request := capture{limit: m.config.MaxBodySize}
	originalLength := r.ContentLength
	if r.Body != nil {
		r.Body = &captureReader{Reader: io.TeeReader(r.Body, &request), closer: r.Body}
	}
	response := &responseCapture{ResponseWriter: w, body: capture{limit: m.config.MaxBodySize}}
	defer func() {
		status := response.status
		if status == 0 {
			status = 200
		}
		reqHeaders, _ := json.Marshal(clean(headers))
		respHeaders, _ := json.Marshal(clean(w.Header()))
		var rpc struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(request.data, &rpc)
		size := request.total
		if originalLength > int64(size) {
			size = int(originalLength)
		}
		record := map[string]interface{}{
			"gateway_origin_id": m.config.GatewayOriginID,
			"host_name":         m.config.HostName, "consumer_name": subject, "request_id": identifier(),
			"request_uri": originalURI, "request_method": originalMethod, "http_version": r.Proto,
			"remote_addr": remoteIP(r.RemoteAddr), "remote_user": subject, "server_port": 9080,
			"time_local": start.Format("02/Jan/2006:15:04:05 -0700"), "duration": time.Since(start).Seconds(),
			"status": status, "body_bytes_sent": response.body.total,
			"request_body": string(request.data), "response_body": string(response.body.data),
			"request_body_original_size": size, "request_body_missing": size > 0 && request.total == 0,
			"request_body_truncated": size > len(request.data), "response_body_original_size": response.body.total,
			"response_body_truncated": response.body.total > len(response.body.data),
			"req_headers":             string(reqHeaders), "resp_headers": string(respHeaders), "mcp_method": rpc.Method,
			"mcp_session_id": headers.Get("Mcp-Session-Id"),
			"http_host":      r.Host, "http_user_agent": headers.Get("User-Agent"), "http_referer": headers.Get("Referer"),
			"http_content_type": headers.Get("Content-Type"), "http_content_length": headers.Get("Content-Length"),
			"http_accept_language": headers.Get("Accept-Language"), "http_accept_encoding": headers.Get("Accept-Encoding"),
			"http_connection": headers.Get("Connection"),
		}
		payload, err := json.Marshal(record)
		if err != nil {
			log.Printf("altprobe: encoding failed: %v", err)
			return
		}
		select {
		case m.queue <- payload:
		default:
			log.Print("altprobe: telemetry queue full; event dropped")
		}
	}()
	// Do not forward lab authentication secrets to upstream services.
	r.Header.Del("Apikey")
	m.next.ServeHTTP(response, r)
}

func (m *middleware) deliver(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case payload := <-m.queue:
			if err := pushRedis(m.config, payload); err != nil {
				log.Printf("altprobe: telemetry delivery failed: %v", err)
			}
		}
	}
}
func pushRedis(c Config, payload []byte) error {
	timeout := time.Duration(c.TimeoutMS) * time.Millisecond
	conn, err := net.DialTimeout("tcp", c.RedisAddress, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var command bytes.Buffer
	command.WriteString("*3\r\n")
	for _, p := range [][]byte{[]byte("RPUSH"), []byte(c.RedisKey), payload} {
		fmt.Fprintf(&command, "$%d\r\n", len(p))
		command.Write(p)
		command.WriteString("\r\n")
	}
	if _, err = io.Copy(conn, &command); err != nil {
		return err
	}
	reply, err := bufio.NewReader(io.LimitReader(conn, 4096)).ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(reply, ":") {
		return fmt.Errorf("redis did not acknowledge RPUSH")
	}
	return nil
}
