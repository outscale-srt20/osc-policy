package finops.outscale.nic_001_test

import rego.v1

import data.finops.outscale.nic_001

test_nic_without_link_fails if {
    count(nic_001.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_nic",
            "id":      "eni-orphan",
            "address": "eni-orphan",
            "values":  {},
        }],
    }
}

test_nic_with_empty_vm_id_fails if {
    count(nic_001.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_nic",
            "id":      "eni-detached",
            "address": "eni-detached",
            "values": {
                "link_nic": {"vm_id": ""},
            },
        }],
    }
}

test_attached_nic_passes if {
    count(nic_001.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_nic",
            "id":      "eni-good",
            "address": "eni-good",
            "values": {
                "link_nic": {"vm_id": "i-12345678"},
            },
        }],
    }
}
