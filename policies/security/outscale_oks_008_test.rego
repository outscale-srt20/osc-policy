package security.outscale.oks_008_test

import rego.v1

import data.security.outscale.oks_008

test_kubernetes_1_28_fails if {
    count(oks_008.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_oks_cluster",
            "id":      "old",
            "address": "old",
            "values": {
                "name":    "old",
                "version": "1.28",
            },
        }],
    }
}

test_kubernetes_1_29_fails if {
    count(oks_008.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_oks_cluster",
            "id":      "older",
            "address": "older",
            "values": {
                "name":    "older",
                "version": "1.29",
            },
        }],
    }
}

test_kubernetes_1_30_passes if {
    count(oks_008.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_oks_cluster",
            "id":      "min-supported",
            "address": "min-supported",
            "values": {
                "name":    "min-supported",
                "version": "1.30",
            },
        }],
    }
}

test_kubernetes_1_32_passes if {
    count(oks_008.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_oks_cluster",
            "id":      "current",
            "address": "current",
            "values": {
                "name":    "current",
                "version": "1.32",
            },
        }],
    }
}
