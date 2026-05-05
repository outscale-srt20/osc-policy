package collector

import (
	"context"
	"fmt"

	osc "github.com/outscale/osc-sdk-go/v2"
)

type LoadBalancers struct{}

func (LoadBalancers) Name() string { return "lbus" }

func (LoadBalancers) Collect(ctx context.Context, client *osc.APIClient) ([]Resource, error) {
	resp, _, err := client.LoadBalancerApi.ReadLoadBalancers(ctx).
		ReadLoadBalancersRequest(osc.ReadLoadBalancersRequest{}).Execute()
	if err != nil {
		return nil, fmt.Errorf("ReadLoadBalancers: %w", err)
	}
	lbs := resp.GetLoadBalancers()
	out := make([]Resource, 0, len(lbs))
	for _, lb := range lbs {
		values := toSnakeMap(lb)
		out = append(out, Resource{
			Type:    "outscale_load_balancer",
			ID:      lb.GetLoadBalancerName(),
			Address: lb.GetLoadBalancerName(),
			Values:  values,
		})
	}
	return out, nil
}
