package listener

import (
	"encoding/base64"
	"testing"
)

// The structure decoder of the listener registry refuses a struct whose fields a template
// leaves out, and every AmneziaWG template leaves most of them out: the block has to
// decode as a map and be converted, or the whole listener fails to start.
func TestAmneziaWGBlockDecodesFromPartialTemplate(t *testing.T) {
	mapping := map[string]any{
		"type":   "wireguard",
		"name":   "awg",
		"port":   "0",
		"listen": "127.0.0.1",
		"users":  map[string]any{"a": "sa"},
		"mtu":    1420,
		"amnezia-wg-option": map[string]any{
			"version": 3, "s1": 20, "s2": 24, "s3": 28, "s4": 32,
			"header-protection-key": base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"random-trailers":       true,
		},
	}
	l, err := ParseListener(mapping)
	if err != nil {
		t.Fatalf("a partial amnezia-wg-option must decode: %v", err)
	}
	if l == nil {
		t.Fatal("no listener")
	}
	_ = l.Close()
}

// A template without a private key reaches the listener as an empty one: the registry
// itself must not fail, the listener reports the missing key when it starts.
func TestWireGuardWithoutKeyParses(t *testing.T) {
	mapping := map[string]any{
		"type":   "wireguard",
		"name":   "wg",
		"port":   "0",
		"listen": "127.0.0.1",
	}
	if _, err := ParseListener(mapping); err != nil {
		t.Fatalf("wireguard must parse without users or a key: %v", err)
	}
}
