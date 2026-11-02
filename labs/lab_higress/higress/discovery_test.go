package main

import "testing"

func TestDiscoveryIdentity(t *testing.T) {
	p := &plugin{config: config{GatewayOriginID: "trusted-gateway-1", HostName: "higress"}}
	ids := map[string]bool{}
	for i := 0; i < 2; i++ {
		s := p.NewHttpContext(7).(*stream)
		s.headers = map[string]string{"x-request-id": "reused-client-id", "gateway-origin-id": "client-spoof"}
		record := s.record()
		id, _ := record["request_id"].(string)
		if record["gateway_origin_id"] != "trusted-gateway-1" || id == "" || id == "reused-client-id" || ids[id] {
			t.Fatalf("invalid discovery record: %+v", record)
		}
		if s.record()["request_id"] != id {
			t.Fatal("observation ID changed during serialization")
		}
		ids[id] = true
	}
}
