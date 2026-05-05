package collector

import (
	"context"
	"fmt"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type Volumes struct{}

func (Volumes) Name() string { return "volumes" }

func (Volumes) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	resp, _, err := client.VolumeApi.ReadVolumes(ctx).ReadVolumesRequest(osc.ReadVolumesRequest{}).Execute()
	if err != nil {
		return nil, fmt.Errorf("ReadVolumes: %w", err)
	}
	vols := resp.GetVolumes()
	out := make([]Resource, 0, len(vols))
	for _, v := range vols {
		values := toSnakeMap(v)
		out = append(out, Resource{
			Type:    "outscale_volume",
			ID:      v.GetVolumeId(),
			Address: v.GetVolumeId(),
			Values:  values,
		})
	}
	return out, nil
}
