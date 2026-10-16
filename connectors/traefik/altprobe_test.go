package traefik_altprobe

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPolicyAndStreamingCapture(t *testing.T) {
	for _, scenario := range []struct {
		name, reply string
		want        int
	}{
		{"allow", `{"result":{"allow":true}}`, 200},
		{"deny", `{"result":{"allow":false,"status_code":403,"reason":"agent_blocked"}}`, 403},
		{"malformed", `{"result":{}}`, 503},
		{"wrong-type", `{"result":{"allow":"true"}}`, 503},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			policy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var doc map[string]interface{}
				if json.NewDecoder(r.Body).Decode(&doc) != nil {
					t.Error("invalid policy envelope")
				}
				input := doc["input"].(map[string]interface{})
				if input["consumer"].(map[string]interface{})["username"] != "trusted" {
					t.Error("client spoofed identity")
				}
				io.WriteString(w, scenario.reply)
			}))
			defer policy.Close()
			c := CreateConfig()
			c.PolicyURL = policy.URL
			c.PolicyPaths = []string{"/mcp"}
			c.Credentials = map[string]string{"secret": "trusted"}
			c.MaxBodySize = 5
			m := &middleware{config: *c, client: policy.Client(), queue: make(chan []byte, 1)}
			called := false
			m.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.Header.Get("Apikey") != "" {
					t.Error("credential forwarded")
				}
				b, _ := io.ReadAll(r.Body)
				if string(b) != "123456789" {
					t.Error("request body modified")
				}
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, "first")
				w.(http.Flusher).Flush()
				io.WriteString(w, "second")
			})
			r := httptest.NewRequest("POST", "http://localhost/mcp", strings.NewReader("123456789"))
			r.Header.Set("Apikey", "secret")
			r.Header.Set("X-Agent-Id", "spoofed")
			w := httptest.NewRecorder()
			m.ServeHTTP(w, r)
			if w.Code != scenario.want {
				t.Fatalf("status %d want %d", w.Code, scenario.want)
			}
			if called != (scenario.want == 200) {
				t.Fatal("unexpected upstream access")
			}
			var record map[string]interface{}
			json.Unmarshal(<-m.queue, &record)
			if record["consumer_name"] != "trusted" {
				t.Fatal("untrusted telemetry identity")
			}
			if strings.Contains(record["req_headers"].(string), "secret") {
				t.Fatal("credential leaked")
			}
			if called && (w.Body.String() != "firstsecond" || !w.Flushed || record["response_body"] != "first" || record["request_body"] != "12345" || record["request_body_truncated"] != true) {
				t.Fatal("capture changed streaming or failed to enforce limit")
			}
		})
	}
}

func TestMissingAndDuplicateCredentials(t *testing.T) {
	c := CreateConfig()
	c.PolicyPaths = []string{"/mcp"}
	c.Credentials = map[string]string{"secret": "trusted"}
	for _, keys := range [][]string{nil, {"bad"}, {"secret", "secret"}} {
		m := &middleware{config: *c, queue: make(chan []byte, 1), next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unauthenticated upstream access") })}
		r := httptest.NewRequest("GET", "/mcp", nil)
		r.Header["Apikey"] = keys
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("status %d", w.Code)
		}
	}
}

func TestUnavailablePolicy(t *testing.T) {
	c := CreateConfig()
	c.PolicyURL = "http://127.0.0.1:1"
	c.PolicyPaths = []string{"/mcp"}
	c.Credentials = map[string]string{"secret": "trusted"}
	m := &middleware{config: *c, client: &http.Client{}, queue: make(chan []byte, 1)}
	r := httptest.NewRequest("GET", "/mcp", nil)
	r.Header.Set("Apikey", "secret")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	c := CreateConfig()
	c.MaxBodySize = -1
	if _, err := New(context.Background(), nil, c, "test"); err == nil {
		t.Fatal("invalid cap accepted")
	}
}
