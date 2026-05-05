package plan

import (
	"encoding/json"
	"fmt"
	"os"
)

// Plan représente un plan Terraform JSON désérialisé (schéma simplifié).
type Plan map[string]any

// Parse lit un plan.json et renvoie la map résultante.
func Parse(path string) (Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lecture plan %s: %w", path, err)
	}
	var p Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing plan JSON: %w", err)
	}
	return p, nil
}
