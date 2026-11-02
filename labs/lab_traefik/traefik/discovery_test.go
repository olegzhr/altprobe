package traefik_altprobe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoveryIdentity(t *testing.T) {
	c := CreateConfig()
	c.GatewayOriginID = "trusted-gateway-1"
	m := &middleware{config: *c, queue: make(chan []byte, 2), next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })}
	ids := map[string]bool{}
	for i := 0; i < 2; i++ {
		request := httptest.NewRequest("GET", "/test-api/status", nil)
		request.Header.Set("X-Request-Id", "reused-client-id")
		request.Header.Set("Gateway-Origin-Id", "client-spoof")
		m.ServeHTTP(httptest.NewRecorder(), request)
		var record struct {
			Origin string `json:"gateway_origin_id"`
			ID     string `json:"request_id"`
		}
		if err := json.Unmarshal(<-m.queue, &record); err != nil {
			t.Fatal(err)
		}
		if record.Origin != c.GatewayOriginID || record.ID == "" || record.ID == "reused-client-id" || ids[record.ID] {
			t.Fatalf("invalid discovery identity: %+v", record)
		}
		ids[record.ID] = true
	}
}
