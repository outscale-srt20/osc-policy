package collector

import (
	"context"
	"fmt"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type Snapshots struct{}

func (Snapshots) Name() string { return "snapshots" }

func (Snapshots) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	resp, _, err := client.SnapshotApi.ReadSnapshots(ctx).
		ReadSnapshotsRequest(osc.ReadSnapshotsRequest{}).Execute()
	if err != nil {
		return nil, fmt.Errorf("ReadSnapshots: %w", err)
	}
	out := []Resource{}
	for _, s := range resp.GetSnapshots() {
		out = append(out, Resource{
			Type:    "outscale_snapshot",
			ID:      s.GetSnapshotId(),
			Address: s.GetSnapshotId(),
			Values:  toSnakeMap(s),
		})
	}
	return out, nil
}
