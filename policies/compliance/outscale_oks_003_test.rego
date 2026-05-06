package compliance.outscale.oks_003_test

import rego.v1

import data.security.outscale.oks_003

test_prod_cluster_mono_az_fails if {
    count(oks_003.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_oks_cluster",
            "id":      "prod-1",
            "address": "prod-1",
            "values": {
                "name":        "prod-1",
                "cp_multi_az": false,
                "tags":        {"env": "prod"},
            },
        }],
    }
}

test_dev_cluster_mono_az_passes if {
    count(oks_003.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_oks_cluster",
            "id":      "dev-1",
            "address": "dev-1",
            "values": {
                "name":        "dev-1",
                "cp_multi_az": false,
                "tags":        {"env": "dev"},
            },
        }],
    }
}

test_staging_cluster_mono_az_passes if {
    count(oks_003.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_oks_cluster",
            "id":      "staging-1",
            "address": "staging-1",
            "values": {
                "name":        "staging-1",
                "cp_multi_az": false,
                "tags":        {"Env": "staging"},
            },
        }],
    }
}

test_multi_az_cluster_passes if {
    count(oks_003.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_oks_cluster",
            "id":      "good",
            "address": "good",
            "values": {
                "name":        "good",
                "cp_multi_az": true,
                "tags":        {"env": "prod"},
            },
        }],
    }
}
