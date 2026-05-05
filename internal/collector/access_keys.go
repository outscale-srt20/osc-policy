package collector

import (
	"context"
	"fmt"
	"time"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type AccessKeys struct{}

func (AccessKeys) Name() string { return "access" }

func (AccessKeys) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	resp, _, err := client.AccessKeyApi.ReadAccessKeys(ctx).
		ReadAccessKeysRequest(osc.ReadAccessKeysRequest{}).Execute()
	if err != nil {
		return nil, fmt.Errorf("ReadAccessKeys: %w", err)
	}
	out := []Resource{}
	for _, k := range resp.GetAccessKeys() {
		values := toSnakeMap(k)
		if lu, ok := values["last_used_date"].(string); ok && lu != "" {
			if t, err := time.Parse(time.RFC3339, lu); err == nil {
				values["last_used_age_days"] = int(time.Since(t).Hours() / 24)
			}
		}
		out = append(out, Resource{
			Type:    "outscale_access_key",
			ID:      k.GetAccessKeyId(),
			Address: k.GetAccessKeyId(),
			Values:  values,
		})
	}
	return out, nil
}
