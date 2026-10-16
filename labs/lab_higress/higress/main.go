// Higress proxy-wasm filter. Policy uses the APISIX OPA envelope; telemetry uses its log schema.
package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm/types"
)

type config struct {
	HostName         string            `json:"host_name"`
	MaxBodySize      int               `json:"max_body_size"`
	PolicyCluster    string            `json:"policy_cluster"`
	PolicyPath       string            `json:"policy_path"`
	PolicyPaths      []string          `json:"policy_paths"`
	Credentials      map[string]string `json:"credentials"`
	CollectorCluster string            `json:"collector_cluster"`
	TimeoutMS        uint32            `json:"timeout_ms"`
}
type vm struct{ types.DefaultVMContext }
type plugin struct {
	types.DefaultPluginContext
	config config
}
type stream struct {
	types.DefaultHttpContext
	config                            config
	headers                           map[string]string
	responseHeaders                   map[string]string
	subject, uri, method, remote      string
	request, response                 []byte
	requestSize, responseSize, status int
	start                             time.Time
}

func main()                                             { proxywasm.SetVMContext(&vm{}) }
func (*vm) NewPluginContext(uint32) types.PluginContext { return &plugin{} }
func (p *plugin) OnPluginStart(int) types.OnPluginStartStatus {
	p.config = config{HostName: "higress", MaxBodySize: 5000, PolicyCluster: "altprobe_policy", PolicyPath: "/v1/data/altprobe/allow", CollectorCluster: "telemetry", TimeoutMS: 2000}
	raw, err := proxywasm.GetPluginConfiguration()
	if err != nil || json.Unmarshal(raw, &p.config) != nil || p.config.MaxBodySize < 1 || p.config.MaxBodySize > 32768 || p.config.TimeoutMS == 0 {
		proxywasm.LogCritical("altprobe: invalid config")
		return types.OnPluginStartStatusFailed
	}
	if len(p.config.PolicyPaths) > 0 && (len(p.config.Credentials) == 0 || p.config.PolicyCluster == "" || p.config.PolicyPath == "") {
		return types.OnPluginStartStatusFailed
	}
	return types.OnPluginStartStatusOK
}
func (p *plugin) NewHttpContext(uint32) types.HttpContext {
	return &stream{config: p.config, start: time.Now(), status: 200}
}
func scrub(headers [][2]string) map[string]string {
	out := make(map[string]string)
	for _, h := range headers {
		key := strings.ToLower(h[0])
		value := h[1]
		if key == "apikey" || key == "authorization" || key == "proxy-authorization" || key == "cookie" || key == "set-cookie" {
			value = "[REDACTED]"
		}
		if old, ok := out[key]; ok {
			out[key] = old + "," + value
		} else {
			out[key] = value
		}
	}
	return out
}
func (s *stream) deny(status uint32, reason string) {
	body, _ := json.Marshal(map[string]string{"reason": reason})
	if err := proxywasm.SendHttpResponse(status, [][2]string{{"content-type", "application/json"}}, body, -1); err != nil {
		proxywasm.LogError("altprobe: local response failed")
	}
}
func (s *stream) OnHttpRequestHeaders(int, bool) types.Action {
	headers, _ := proxywasm.GetHttpRequestHeaders()
	s.headers = scrub(headers)
	s.uri = s.headers[":path"]
	s.method = s.headers[":method"]
	ip, _ := proxywasm.GetProperty([]string{"source", "address"})
	s.remote = string(ip)
	count := 0
	key := ""
	for _, h := range headers {
		if strings.EqualFold(h[0], "apikey") {
			count++
			key = h[1]
		}
	}
	if count == 1 {
		s.subject = s.config.Credentials[key]
	}
	_ = proxywasm.RemoveHttpRequestHeader("apikey")
	path := strings.SplitN(s.uri, "?", 2)[0]
	protected := false
	for _, p := range s.config.PolicyPaths {
		if path == p {
			protected = true
			break
		}
	}
	if !protected {
		return types.ActionContinue
	}
	if s.subject == "" {
		s.deny(401, "authentication_required")
		return types.ActionPause
	}
	input := map[string]interface{}{"input": map[string]interface{}{
		"type": "http", "consumer": map[string]string{"username": s.subject},
		"request": map[string]interface{}{"method": s.method, "path": s.uri, "headers": s.headers},
		"var":     map[string]string{"remote_addr": s.remote},
	}}
	body, _ := json.Marshal(input)
	_, err := proxywasm.DispatchHttpCall(s.config.PolicyCluster, [][2]string{
		{":method", "POST"}, {":path", s.config.PolicyPath}, {":authority", "altprobe-policy"}, {"content-type", "application/json"},
	}, body, nil, s.config.TimeoutMS, func(_ int, size int, _ int) {
		headers, e := proxywasm.GetHttpCallResponseHeaders()
		status := ""
		for _, h := range headers {
			if h[0] == ":status" {
				status = h[1]
			}
		}
		if e != nil || status != "200" || size > 65536 {
			s.deny(503, "policy_unavailable")
			return
		}
		raw, e := proxywasm.GetHttpCallResponseBody(0, size)
		var doc struct {
			Result struct {
				Allow  *bool  `json:"allow"`
				Reason string `json:"reason"`
				Status uint32 `json:"status_code"`
			} `json:"result"`
		}
		if e != nil || json.Unmarshal(raw, &doc) != nil || doc.Result.Allow == nil {
			s.deny(503, "policy_unavailable")
			return
		}
		if !*doc.Result.Allow {
			code := doc.Result.Status
			if code < 400 || code > 599 {
				code = 403
			}
			s.deny(code, doc.Result.Reason)
			return
		}
		if proxywasm.ResumeHttpRequest() != nil {
			proxywasm.LogError("altprobe: resume failed")
		}
	})
	if err != nil {
		s.deny(503, "policy_unavailable")
	}
	return types.ActionPause
}
func appendBounded(previous, chunk []byte, limit int) []byte {
	n := limit - len(previous)
	if n > len(chunk) {
		n = len(chunk)
	}
	if n > 0 {
		previous = append(previous, chunk[:n]...)
	}
	return previous
}
func (s *stream) OnHttpRequestBody(size int, _ bool) types.Action {
	s.requestSize += size
	n := s.config.MaxBodySize - len(s.request)
	if n > size {
		n = size
	}
	if n > 0 {
		body, err := proxywasm.GetHttpRequestBody(0, n)
		if err == nil {
			s.request = appendBounded(s.request, body, s.config.MaxBodySize)
		}
	}
	return types.ActionContinue
}
func (s *stream) OnHttpResponseHeaders(int, bool) types.Action {
	headers, _ := proxywasm.GetHttpResponseHeaders()
	s.responseHeaders = scrub(headers)
	if code, err := strconv.Atoi(s.responseHeaders[":status"]); err == nil {
		s.status = code
	}
	return types.ActionContinue
}
func (s *stream) OnHttpResponseBody(size int, _ bool) types.Action {
	s.responseSize += size
	n := s.config.MaxBodySize - len(s.response)
	if n > size {
		n = size
	}
	if n > 0 {
		body, err := proxywasm.GetHttpResponseBody(0, n)
		if err == nil {
			s.response = appendBounded(s.response, body, s.config.MaxBodySize)
		}
	}
	return types.ActionContinue
}
func (s *stream) OnHttpStreamDone() {
	headers, _ := json.Marshal(s.headers)
	responseHeaders, _ := json.Marshal(s.responseHeaders)
	var rpc struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(s.request, &rpc)
	size := s.requestSize
	if length, err := strconv.Atoi(s.headers["content-length"]); err == nil && length > size {
		size = length
	}
	session := s.headers["session-id"]
	if session == "" {
		session = s.headers["x-session-id"]
	}
	record := map[string]interface{}{
		"host_name": s.config.HostName, "consumer_name": s.subject, "request_uri": s.uri, "request_method": s.method,
		"request_id": s.headers["x-request-id"], "http_version": "HTTP/1.1", "remote_addr": s.remote, "server_port": 9080,
		"remote_user": s.subject, "time_local": s.start.Format("02/Jan/2006:15:04:05 -0700"), "duration": time.Since(s.start).Seconds(),
		"status": s.status, "body_bytes_sent": s.responseSize, "request_body": string(s.request), "response_body": string(s.response),
		"request_body_original_size": size, "request_body_missing": size > 0 && s.requestSize == 0,
		"request_body_truncated": size > len(s.request), "response_body_original_size": s.responseSize, "response_body_truncated": s.responseSize > len(s.response),
		"req_headers": string(headers), "resp_headers": string(responseHeaders), "mcp_method": rpc.Method,
		"mcp_session_id": s.headers["mcp-session-id"], "http_x_agent_id": s.headers["x-agent-id"],
		"http_x_claude_code_agent_id": s.headers["x-claude-code-agent-id"], "http_x_claude_code_session_id": s.headers["x-claude-code-session-id"],
		"http_session_id": session, "http_host": s.headers[":authority"], "http_user_agent": s.headers["user-agent"],
		"http_referer": s.headers["referer"], "http_content_type": s.headers["content-type"], "http_content_length": s.headers["content-length"],
		"http_x_forwarded_for": s.headers["x-forwarded-for"], "http_x_real_ip": s.headers["x-real-ip"],
		"http_accept_language": s.headers["accept-language"], "http_accept_encoding": s.headers["accept-encoding"],
		"http_connection": s.headers["connection"], "http_authorization": "[REDACTED]", "http_cookie": "[REDACTED]",
	}
	raw, err := json.Marshal(record)
	if err != nil {
		proxywasm.LogError("altprobe: telemetry encoding failed")
		return
	}
	_, err = proxywasm.DispatchHttpCall(s.config.CollectorCluster, [][2]string{
		{":method", "POST"}, {":path", "/events"}, {":authority", "telemetry"}, {"content-type", "application/json"},
	}, raw, nil, s.config.TimeoutMS, func(_ int, _ int, _ int) {
		headers, _ := proxywasm.GetHttpCallResponseHeaders()
		ok := false
		for _, h := range headers {
			if h[0] == ":status" && h[1] == "204" {
				ok = true
			}
		}
		if !ok {
			proxywasm.LogError("altprobe: telemetry collector rejected event")
		}
	})
	if err != nil {
		proxywasm.LogError("altprobe: telemetry dispatch failed")
	}
}
