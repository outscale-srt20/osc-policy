package security.outscale.sg_001_test

import rego.v1

import data.security.outscale.sg_001

test_ssh_open_to_internet_fails if {
    count(sg_001.deny) > 0 with input as {
        "planned_values": {
            "root_module": {
                "resources": [{
                    "type":    "outscale_security_group_rule",
                    "address": "outscale_security_group_rule.test",
                    "values": {
                        "flow":            "Inbound",
                        "ip_range":        "0.0.0.0/0",
                        "from_port_range": "22",
                        "ip_protocol":     "tcp",
                    },
                }],
            },
        },
    }
}

test_ssh_restricted_passes if {
    count(sg_001.deny) == 0 with input as {
        "planned_values": {
            "root_module": {
                "resources": [{
                    "type":    "outscale_security_group_rule",
                    "address": "outscale_security_group_rule.test",
                    "values": {
                        "flow":            "Inbound",
                        "ip_range":        "10.0.0.0/8",
                        "from_port_range": "22",
                        "ip_protocol":     "tcp",
                    },
                }],
            },
        },
    }
}
