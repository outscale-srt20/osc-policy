package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	osc "github.com/outscale/osc-sdk-go/v2"
)

// OKS collects Outscale Kubernetes Service resources via the dedicated OKS REST
// API (https://api.<region>.oks.outscale.com/api/v2/), which uses simple
// AccessKey/SecretKey HTTP headers for auth (no SigV4).
//
// Scope: outscale_oks_project, outscale_oks_cluster.
// Nodepools are Kubernetes CRDs (not REST), so out of scope here.
type OKS struct{}

func (OKS) Name() string { return "oks" }

func (OKS) Collect(ctx context.Context, _ *osc.APIClient) ([]Resource, error) {
	// Extract credentials from the SDK ctx (populated by oscAuthContext).
	awsv4Val := ctx.Value(osc.ContextAWSv4)
	if awsv4Val == nil {
		return nil, fmt.Errorf("OKS collector: AWSv4 credentials missing from context")
	}
	awsv4, ok := awsv4Val.(osc.AWSv4)
	if !ok {
		return nil, fmt.Errorf("OKS collector: unexpected ContextAWSv4 type")
	}

	region := "eu-west-2"
	if vars, ok := ctx.Value(osc.ContextServerVariables).(map[string]string); ok {
		if r := vars["region"]; r != "" {
			region = r
		}
	}

	endpoint := fmt.Sprintf("https://api.%s.oks.outscale.com/api/v2", region)
	client := &oksClient{
		endpoint:  endpoint,
		accessKey: awsv4.AccessKey,
		secretKey: awsv4.SecretKey,
		http:      &http.Client{Timeout: 30 * time.Second},
	}

	out := []Resource{}

	// 1. Collect projects
	projects, err := client.listProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("OKS list projects: %w", err)
	}
	for _, p := range projects {
		out = append(out, Resource{
			Type:    "outscale_oks_project",
			ID:      stringField(p, "id"),
			Address: stringField(p, "name"),
			Values:  p,
		})
	}

	// 2. For each project, collect clusters
	for _, p := range projects {
		projectID := stringField(p, "id")
		if projectID == "" {
			continue
		}
		clusters, err := client.listClusters(ctx, projectID)
		if err != nil {
			// Don't fail the whole collector for one project
			continue
		}
		for _, c := range clusters {
			out = append(out, Resource{
				Type:    "outscale_oks_cluster",
				ID:      stringField(c, "id"),
				Address: stringField(c, "name"),
				Values:  c,
			})
		}
	}

	return out, nil
}

// ---- HTTP client ----

type oksClient struct {
	endpoint  string
	accessKey string
	secretKey string
	http      *http.Client
}

func (c *oksClient) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("AccessKey", c.accessKey)
	req.Header.Set("SecretKey", c.secretKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("OKS API %s: HTTP %d: %s", path, resp.StatusCode, truncate(string(body), 200))
	}
	return body, nil
}

func (c *oksClient) listProjects(ctx context.Context) ([]map[string]interface{}, error) {
	body, err := c.get(ctx, "/projects")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Projects []map[string]interface{} `json:"Projects"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode projects: %w", err)
	}
	return resp.Projects, nil
}

func (c *oksClient) listClusters(ctx context.Context, projectID string) ([]map[string]interface{}, error) {
	body, err := c.get(ctx, "/clusters?project_id="+projectID)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Clusters []map[string]interface{} `json:"Clusters"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode clusters: %w", err)
	}
	return resp.Clusters, nil
}

// ---- helpers ----

func stringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
