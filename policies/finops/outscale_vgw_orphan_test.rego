package finops.outscale.vgw_orphan_test

import rego.v1

import data.finops.outscale.vgw_orphan

test_vgw_without_links_fails if {
    count(vgw_orphan.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_virtual_gateway",
            "id":      "vgw-orphan",
            "address": "vgw-orphan",
            "values":  {},
        }],
    }
}

test_vgw_with_empty_links_fails if {
    count(vgw_orphan.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_virtual_gateway",
            "id":      "vgw-empty",
            "address": "vgw-empty",
            "values": {
                "net_to_virtual_gateway_links": [],
            },
        }],
    }
}

test_vgw_with_link_passes if {
    count(vgw_orphan.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_virtual_gateway",
            "id":      "vgw-good",
            "address": "vgw-good",
            "values": {
                "net_to_virtual_gateway_links": [
                    {"net_id": "vpc-12345"},
                ],
            },
        }],
    }
}
