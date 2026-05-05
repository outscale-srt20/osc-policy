package security.outscale.oks_001_test

import rego.v1

import data.security.outscale.oks_001

test_admin_whitelist_open_to_world_fails if {
    count(oks_001.deny) > 0 with input as {
        "planned_values": {
            "root_module": {
                "resources": [{
                    "type":    "outscale_oks_cluster",
                    "address": "outscale_oks_cluster.bad",
                    "values": {
                        "name":            "prod",
                        "admin_whitelist": ["0.0.0.0/0"],
                    },
                }],
            },
        },
    }
}

test_admin_whitelist_ipv6_open_fails if {
    count(oks_001.deny) > 0 with input as {
        "planned_values": {
            "root_module": {
                "resources": [{
                    "type":    "outscale_oks_cluster",
                    "address": "outscale_oks_cluster.bad6",
                    "values": {
                        "name":            "prod",
                        "admin_whitelist": ["::/0"],
                    },
                }],
            },
        },
    }
}

test_admin_whitelist_specific_cidrs_passes if {
    count(oks_001.deny) == 0 with input as {
        "planned_values": {
            "root_module": {
                "resources": [{
                    "type":    "outscale_oks_cluster",
                    "address": "outscale_oks_cluster.good",
                    "values": {
                        "name":            "prod",
                        "admin_whitelist": ["10.0.0.5/32", "203.0.113.42/32"],
                    },
                }],
            },
        },
    }
}

test_live_resource_with_open_whitelist_fails if {
    count(oks_001.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_oks_cluster",
            "id":      "uuid-1234",
            "address": "chatbot-rag",
            "values": {
                "name":            "chatbot-rag",
                "admin_whitelist": ["0.0.0.0/0"],
            },
        }],
    }
}
