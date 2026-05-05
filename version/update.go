package version

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const githubLatest = "https://api.github.com/repos/outscale-srt20/osc-policy/releases/latest"

// CheckResult est le résultat du check de mise à jour.
type CheckResult struct {
	Latest  string // tag de la dernière release
	Current string // version courante
	Newer   bool   // true si une version plus récente existe
}

// CheckLatest interroge l'API GitHub pour détecter une nouvelle release.
// Retourne nil en cas d'erreur réseau (non-bloquant).
// Désactivable via OSC_POLICY_NO_UPDATE_CHECK=1.
func CheckLatest(ctx context.Context) *CheckResult {
	if os.Getenv("OSC_POLICY_NO_UPDATE_CHECK") == "1" {
		return nil
	}
	// Ignorer les builds de développement ou locaux (dirty).
	if Version == "dev" || Version == "" || strings.Contains(Version, "+") {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubLatest, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "osc-policy/"+Version)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}

	latest := strings.TrimPrefix(payload.TagName, "v")
	current := strings.TrimPrefix(Version, "v")

	return &CheckResult{
		Latest:  latest,
		Current: current,
		Newer:   latest != current && isNewer(latest, current),
	}
}

// isNewer retourne true si candidate > current (comparaison semver basique).
func isNewer(candidate, current string) bool {
	cv := parseSemver(candidate)
	cc := parseSemver(current)
	for i := range cv {
		if i >= len(cc) {
			return true
		}
		if cv[i] > cc[i] {
			return true
		}
		if cv[i] < cc[i] {
			return false
		}
	}
	return false
}

func parseSemver(v string) []int {
	var parts []int
	for _, s := range strings.Split(v, ".") {
		var n int
		_, _ = fmt.Sscanf(s, "%d", &n)
		parts = append(parts, n)
	}
	return parts
}
