package cloudconfig

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzParse exercises the administrator-controlled input boundary. Successful
// parses must have stable defaults and survive both supported wire encodings
// without changing network ranges, identities, labels or bootstrap intent.
func FuzzParse(f *testing.F) {
	example, err := os.ReadFile("../../examples/cloud.yaml")
	if err != nil {
		f.Fatal(err)
	}
	if _, err := Parse(example); err != nil {
		f.Fatalf("shipped cloud.yaml example is invalid: %v", err)
	}
	for _, seed := range [][]byte{
		example,
		[]byte(validManifest),
		[]byte(validManifest + "\nunknown: value\n"),
		[]byte(validManifest + "\nname: duplicate\n"),
		[]byte(strings.Replace(validManifest, "    labels:\n      location: home\n      example.com/pool: personal", "    labels: {}", 1)),
		[]byte("nodes: &nodes\n  hub: *nodes\n"),
		[]byte("nodes: [\n"),
		[]byte("---\n---\n"),
		{0xff, 0, 0xfe},
		nil,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cloud, err := Parse(data)
		if err != nil {
			if cloud != nil {
				t.Fatal("failed parse returned a usable partial cloud")
			}
			return
		}
		before, err := json.Marshal(cloud)
		if err != nil {
			t.Fatal(err)
		}
		if err := Validate(cloud); err != nil {
			t.Fatalf("parse accepted invalid cloud: %v", err)
		}
		after, err := json.Marshal(cloud)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("validation mutated the cloud: %v", err)
		}
		repeated, err := Parse(data)
		if err != nil {
			t.Fatalf("same input failed on second parse: %v", err)
		}
		repeatedJSON, err := json.Marshal(repeated)
		if err != nil || !bytes.Equal(before, repeatedJSON) {
			t.Fatalf("parse is nondeterministic: %v", err)
		}
		for _, marshal := range []func(any) ([]byte, error){json.Marshal, yaml.Marshal} {
			encoded, err := marshal(cloud)
			if err != nil {
				t.Fatal(err)
			}
			// A different encoding may expand a size-limit input. Size-limit
			// rejection is covered separately; only compare parseable sizes.
			if len(encoded) > MaxManifestSize {
				continue
			}
			roundTrip, err := Parse(encoded)
			if err != nil {
				t.Fatalf("normalized cloud cannot be parsed again: %v\n%s", err, encoded)
			}
			canonical, err := json.Marshal(roundTrip)
			if err != nil || !bytes.Equal(before, canonical) {
				t.Fatalf("round trip changed cloud configuration: %v\nbefore: %s\nafter: %s", err, before, canonical)
			}
		}
	})
}
