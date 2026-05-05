package finops.outscale.cgw_orphan_test

import rego.v1

import data.finops.outscale.cgw_orphan

test_cgw_without_vpn_fails if {
    count(cgw_orphan.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_client_gateway",
            "id":      "cgw-orphan",
            "address": "cgw-orphan",
            "values": {
                "client_gateway_id": "cgw-orphan",
                "public_ip":         "203.0.113.10",
            },
        }],
    }
}

test_cgw_with_vpn_passes if {
    count(cgw_orphan.deny) == 0 with input as {
        "resources": [
            {
                "type":    "outscale_client_gateway",
                "id":      "cgw-used",
                "address": "cgw-used",
                "values": {
                    "client_gateway_id": "cgw-used",
                    "public_ip":         "203.0.113.20",
                },
            },
            {
                "type":    "outscale_vpn_connection",
                "id":      "vpn-1",
                "address": "vpn-1",
                "values": {
                    "client_gateway_id": "cgw-used",
                },
            },
        ],
    }
}
