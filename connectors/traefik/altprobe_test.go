package traefik_altprobe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCredentialAttribution(t *testing.T) {
	c := CreateConfig()
	c.Credentials = map[string]string{"secret": "trusted"}
	for _, tc := range []struct {
		keys    []string
		subject string
	}{
		{nil, ""}, {[]string{"bad"}, ""}, {[]string{"secret", "secret"}, ""}, {[]string{"secret"}, "trusted"},
	} {
		m := &middleware{config: *c, queue: make(chan []byte, 1), next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.Header.Values("Apikey")) != 0 {
				t.Error("credential forwarded upstream")
			}
			w.WriteHeader(http.StatusNoContent)
		})}
		r := httptest.NewRequest("GET", "/mcp", nil)
		r.Header["Apikey"] = tc.keys
		w := httptest.NewRecorder()
		m.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status %d", w.Code)
		}
		var record map[string]interface{}
		if err := json.Unmarshal(<-m.queue, &record); err != nil || record["consumer_name"] != tc.subject {
			t.Fatalf("consumer_name = %v, want %q (error: %v)", record["consumer_name"], tc.subject, err)
		}
	}
}

func TestInvalidConfiguration(t *testing.T) {
	c := CreateConfig()
	c.MaxBodySize = -1
	if _, err := New(context.Background(), nil, c, "test"); err == nil {
		t.Fatal("invalid cap accepted")
	}
}
