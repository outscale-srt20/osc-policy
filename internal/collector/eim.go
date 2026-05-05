package collector

import (
	"context"
	"encoding/json"
	"fmt"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type EIM struct{}

func (EIM) Name() string { return "eim" }

// Collect interroge les APIs EIM : Policies (avec document JSON normalisé) et
// Users. Le document de chaque policy est lu via ReadPolicyVersion sur la
// version par défaut, puis les Statement sont aplatis en {effect, actions[],
// resources[]} pour simplifier l'écriture des règles Rego.
//
// APIs non couvertes (limites du SDK osc-sdk-go/v2 @ v2.24) :
//   - pas de ListMFADevices → détection MFA utilisateur impossible
//   - pas de distinction compte principal vs EIM user via ReadAccessKeys
//   - ReadApiLogs trop volumineux pour un audit par identité sans pagination lourde
//
// Ces limites sont documentées dans docs/ROADMAP.md (section Sprint 4).
func (EIM) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	var out []Resource
	var firstErr error

	// Policies — scope LOCAL = policies créées par le compte (pas les managed OWS).
	scope := "LOCAL"
	polResp, _, err := client.PolicyApi.ReadPolicies(ctx).
		ReadPoliciesRequest(osc.ReadPoliciesRequest{
			Filters: &osc.ReadPoliciesFilters{Scope: &scope},
		}).Execute()
	if err != nil {
		firstErr = fmt.Errorf("ReadPolicies: %w", err)
	} else {
		for _, p := range polResp.GetPolicies() {
			values := toSnakeMap(p)
			if p.GetOrn() != "" && p.GetPolicyDefaultVersionId() != "" {
				vResp, _, verr := client.PolicyApi.ReadPolicyVersion(ctx).
					ReadPolicyVersionRequest(osc.ReadPolicyVersionRequest{
						PolicyOrn: p.GetOrn(),
						VersionId: p.GetPolicyDefaultVersionId(),
					}).Execute()
				if verr == nil {
					pv := vResp.GetPolicyVersion()
					body := pv.GetBody()
					if body != "" {
						values["document_body"] = body
						if stmts, perr := parseEIMStatements(body); perr == nil {
							values["statements"] = stmts
						}
					}
				}
			}
			out = append(out, Resource{
				Type:    "outscale_eim_policy",
				ID:      p.GetPolicyId(),
				Address: p.GetPolicyName(),
				Values:  values,
			})
		}
	}

	// Users — exposés pour les règles Sprint 4 (OSC-EIM-011, 013, 015).
	userResp, _, err := client.UserApi.ReadUsers(ctx).
		ReadUsersRequest(osc.ReadUsersRequest{}).Execute()
	if err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("ReadUsers: %w", err)
		}
	} else {
		for _, u := range userResp.GetUsers() {
			values := toSnakeMap(u)
			out = append(out, Resource{
				Type:    "outscale_eim_user",
				ID:      u.GetUserId(),
				Address: u.GetUserName(),
				Values:  values,
			})
		}
	}

	return out, firstErr
}

// parseEIMStatements normalise un document EIM JSON en liste uniforme de
// statements. Source et cible étant hétérogènes (Action/Resource peuvent
// être string ou array, Statement peut être objet ou array), la sortie
// garantit : effect string, actions []interface{}, resources []interface{}.
func parseEIMStatements(body string) ([]map[string]interface{}, error) {
	var doc struct {
		Statement interface{} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return nil, err
	}
	raw := []interface{}{}
	switch s := doc.Statement.(type) {
	case []interface{}:
		raw = s
	case map[string]interface{}:
		raw = []interface{}{s}
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, st := range raw {
		m, ok := st.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, map[string]interface{}{
			"effect":    strValue(m, "Effect"),
			"actions":   toStringList(m, "Action"),
			"resources": toStringList(m, "Resource"),
		})
	}
	return out, nil
}

func strValue(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func toStringList(m map[string]interface{}, key string) []interface{} {
	v, ok := m[key]
	if !ok {
		return []interface{}{}
	}
	switch x := v.(type) {
	case string:
		return []interface{}{x}
	case []interface{}:
		return x
	}
	return []interface{}{}
}
