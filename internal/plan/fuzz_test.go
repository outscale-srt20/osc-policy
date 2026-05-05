package plan

import (
	"encoding/json"
	"testing"
)

// FuzzParse vérifie que le parsing de JSON arbitraire ne panique jamais.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"planned_values":{"root_module":{"resources":[]}}}`))
	f.Add([]byte(`{"planned_values":{"root_module":{"resources":[{"address":"aws_instance.foo","type":"aws_instance","name":"foo","mode":"managed","values":{"ami":"ami-123"}}]}}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var p Plan
		if err := json.Unmarshal(data, &p); err != nil {
			return
		}
		_ = ExtractAll(p)
	})
}

// FuzzExtractAll vérifie que l'extraction de ressources ne panique jamais.
func FuzzExtractAll(f *testing.F) {
	f.Add(`{}`)
	f.Add(`{"planned_values":null}`)
	f.Add(`{"planned_values":{"root_module":{"child_modules":[{"resources":[]}]}}}`)
	f.Add(`{"resource_changes":[{"address":"x","change":{"actions":["create"]}}],"planned_values":{"root_module":{"resources":[{"address":"x","type":"t","name":"n","mode":"managed","values":{}}]}}}`)

	f.Fuzz(func(t *testing.T, s string) {
		var p Plan
		if err := json.Unmarshal([]byte(s), &p); err != nil {
			return
		}
		_ = ExtractAll(p)
	})
}
