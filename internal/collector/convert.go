package collector

import (
	"encoding/json"
	"strings"
	"unicode"
)

// toSnakeMap convertit un objet (struct, map) en map[string]interface{} avec
// des clés snake_case récursivement. Utile pour normaliser les réponses
// Outscale (PascalCase) vers le format attendu par les policies Rego.
func toSnakeMap(v interface{}) map[string]interface{} {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil
	}
	converted := convertKeys(generic)
	out, ok := converted.(map[string]interface{})
	if !ok {
		return nil
	}
	return out
}

func convertKeys(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, vv := range val {
			out[toSnake(k)] = convertKeys(vv)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, vv := range val {
			out[i] = convertKeys(vv)
		}
		return out
	default:
		return v
	}
}

func toSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				prev := rune(s[i-1])
				if !unicode.IsUpper(prev) && prev != '_' {
					b.WriteByte('_')
				}
			}
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// normalizeTags convertit la forme API (Key/Value) vers la forme policy (key/value).
func normalizeTags(values map[string]interface{}) {
	t, ok := values["tags"]
	if !ok {
		return
	}
	arr, ok := t.([]interface{})
	if !ok {
		return
	}
	for i, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if v, ok := m["key"]; ok {
			m["key"] = v
		}
		if v, ok := m["value"]; ok {
			m["value"] = v
		}
		arr[i] = m
	}
	values["tags"] = arr
}
