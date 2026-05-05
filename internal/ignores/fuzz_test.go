package ignores

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzParseIgnores vérifie que le parsing YAML arbitraire ne panique jamais.
func FuzzParseIgnores(f *testing.F) {
	f.Add([]byte(`ignores: []`))
	f.Add([]byte(`ignores:
  - rule: OSC-SG-001
    resource: aws_security_group.foo
    reason: exception validée
    expires: "2026-12-31"
`))
	f.Add([]byte(`ignores: null`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		var file File
		_ = yaml.Unmarshal(data, &file)
		for _, ig := range file.Ignores {
			_ = ig.Rule
			_ = ig.Resource
			_ = ig.Reason
			_ = ig.Expires
		}
	})
}
