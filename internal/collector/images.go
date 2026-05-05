package collector

import (
	"context"
	"fmt"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type Images struct{}

func (Images) Name() string { return "images" }

func (Images) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	resp, _, err := client.ImageApi.ReadImages(ctx).
		ReadImagesRequest(osc.ReadImagesRequest{}).Execute()
	if err != nil {
		return nil, fmt.Errorf("ReadImages: %w", err)
	}
	out := []Resource{}
	for _, img := range resp.GetImages() {
		out = append(out, Resource{
			Type:    "outscale_image",
			ID:      img.GetImageId(),
			Address: img.GetImageId(),
			Values:  toSnakeMap(img),
		})
	}
	return out, nil
}
