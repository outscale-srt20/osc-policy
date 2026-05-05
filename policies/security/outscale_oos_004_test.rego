package security.outscale.oos_004_test

import rego.v1

import data.security.outscale.oos_004

test_bucket_with_public_policy_fails if {
    count(oos_004.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_oos",
            "id":      "lms-assets",
            "address": "lms-assets",
            "values": {
                "bucket":        "lms-assets",
                "policy_public": true,
            },
        }],
    }
}

test_bucket_with_restricted_policy_passes if {
    count(oos_004.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_oos",
            "id":      "internal",
            "address": "internal",
            "values": {
                "bucket":        "internal",
                "policy_public": false,
            },
        }],
    }
}

test_bucket_without_policy_passes if {
    count(oos_004.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_oos",
            "id":      "no-policy",
            "address": "no-policy",
            "values": {
                "bucket": "no-policy",
            },
        }],
    }
}
