package privateaccess

import (
	"strings"
	"testing"
	"time"
)

func TestAdmissionFromValuesRejectsMalformedWireFields(t *testing.T) {
	now := time.Now().UTC()
	type wire struct {
		hash, hostname, match, suffix, protocol, kind, tunnelName, routeName, operation, connector string
		endpoints                                                                                  []string
	}
	valid := func() wire {
		return wire{hash: "sha256:" + strings.Repeat("a", 64), hostname: "web.example.test", match: "exact", protocol: "http", kind: "tunnel", tunnelName: "payments", routeName: "postgres", connector: "connector_1", endpoints: []string{"tls://edge.example.test:25001", "quic://edge.example.test:25002"}}
	}
	for name, mutate := range map[string]func(*wire){
		"uppercase hash": func(v *wire) { v.hash = "sha256:" + strings.Repeat("A", 64) },
		"nonhex hash":    func(v *wire) { v.hash = "sha256:" + strings.Repeat("z", 64) },
		"missing port":   func(v *wire) { v.endpoints[0] = "tls://edge.example.test" },
		"zero port":      func(v *wire) { v.endpoints[0] = "tls://edge.example.test:0" },
		"unknown match":  func(v *wire) { v.match = "recursive" },
		"missing tunnel name": func(v *wire) {
			v.tunnelName = ""
		},
		"invalid route name": func(v *wire) {
			v.routeName = "route name"
		},
		"recursive wildcard": func(v *wire) {
			v.match = "one_label_wildcard"
			v.hostname = "**.example.test"
			v.suffix = "example.test"
		},
		"invalid suffix": func(v *wire) {
			v.match = "one_label_wildcard"
			v.hostname = "*.example.test"
			v.suffix = "*.example.test"
		},
		"protocol resource mismatch": func(v *wire) {
			v.kind = "preview"
			v.operation = "operation_1"
			v.connector = ""
			v.tunnelName = ""
			v.routeName = ""
			v.protocol = "private_tcp"
			v.hostname = ""
			v.match = "catch_all"
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := valid()
			mutate(&v)
			_, err := admissionFromValues(now, "account_1", v.kind, "tunnel_1", v.tunnelName, v.routeName, v.operation, v.connector, "session_1", "route_1", 1, 1, 1, 1, 1, "edge_1", "epoch_1", v.protocol, v.hostname, v.endpoints, now.Add(time.Minute), "tunnel_1", "connector_1", "assignment_1", v.hash, v.match, v.suffix, "machine_1", 1, "ugS1P3D8QWeKLIzyLOMZD8l_wp1lo6uY6NdicTbDz58", "sha256:"+strings.Repeat("b", 64), "test-public-certificate-chain")
			if err == nil {
				t.Fatal("malformed admission accepted")
			}
		})
	}
}
