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


func TestInvalidConfiguration(t *testing.T) {
	c := CreateConfig()
	c.MaxBodySize = -1
	if _, err := New(context.Background(), nil, c, "test"); err == nil {
		t.Fatal("invalid cap accepted")
	}
}
