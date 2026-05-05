package plan

// Resource est une ressource terraform extraite (planned_values ou resource_changes).
type Resource struct {
	Address string         `json:"address"`
	Type    string         `json:"type"`
	Name    string         `json:"name"`
	Mode    string         `json:"mode"`
	Values  map[string]any `json:"values"`
	Change  string         `json:"change,omitempty"` // create, update, delete, no-op
}

// ExtractAll retourne toutes les ressources du plan en parcourant récursivement
// planned_values.root_module.child_modules. Utilise resource_changes pour
// récupérer le type de changement quand il est disponible.
func ExtractAll(p Plan) []Resource {
	var resources []Resource

	// Index des changements par adresse pour récupérer "actions"
	changesByAddress := map[string]string{}
	if rc, ok := p["resource_changes"].([]any); ok {
		for _, item := range rc {
			m, _ := item.(map[string]any)
			if m == nil {
				continue
			}
			addr, _ := m["address"].(string)
			ch, _ := m["change"].(map[string]any)
			if ch == nil {
				continue
			}
			actions, _ := ch["actions"].([]any)
			if len(actions) > 0 {
				if a, ok := actions[0].(string); ok {
					changesByAddress[addr] = a
				}
			}
		}
	}

	pv, ok := p["planned_values"].(map[string]any)
	if !ok {
		return resources
	}
	root, ok := pv["root_module"].(map[string]any)
	if !ok {
		return resources
	}

	var walk func(module map[string]any)
	walk = func(module map[string]any) {
		if res, ok := module["resources"].([]any); ok {
			for _, item := range res {
				m, _ := item.(map[string]any)
				if m == nil {
					continue
				}
				r := Resource{
					Address: getString(m, "address"),
					Type:    getString(m, "type"),
					Name:    getString(m, "name"),
					Mode:    getString(m, "mode"),
				}
				if v, ok := m["values"].(map[string]any); ok {
					r.Values = v
				}
				r.Change = changesByAddress[r.Address]
				resources = append(resources, r)
			}
		}
		if children, ok := module["child_modules"].([]any); ok {
			for _, c := range children {
				if cm, ok := c.(map[string]any); ok {
					walk(cm)
				}
			}
		}
	}
	walk(root)
	return resources
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// FilterChangesOnly filtre les ressources qui ne sont pas en no-op.
func FilterChangesOnly(resources []Resource) []Resource {
	out := make([]Resource, 0, len(resources))
	for _, r := range resources {
		if r.Change == "" || r.Change == "no-op" {
			continue
		}
		out = append(out, r)
	}
	return out
}
