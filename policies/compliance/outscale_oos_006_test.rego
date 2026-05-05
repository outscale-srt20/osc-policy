package compliance.outscale.oos_006_test

import rego.v1

import data.compliance.outscale.oos_006

test_bucket_without_required_tags_fails if {
    count(oos_006.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_oos",
            "id":      "no-tags",
            "address": "no-tags",
            "values": {
                "bucket": "no-tags",
                "tags":   {"foo": "bar"},
            },
        }],
    }
}

test_bucket_with_partial_tags_fails if {
    count(oos_006.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_oos",
            "id":      "partial",
            "address": "partial",
            "values": {
                "bucket": "partial",
                "tags": {
                    "CostCenter": "cc-1234",
                    "Project":    "site",
                    # missing Env, Owner
                },
            },
        }],
    }
}

test_bucket_with_all_required_tags_passes if {
    count(oos_006.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_oos",
            "id":      "compliant",
            "address": "compliant",
            "values": {
                "bucket": "compliant",
                "tags": {
                    "CostCenter": "cc-1234",
                    "Project":    "site",
                    "Env":        "prod",
                    "Owner":      "team-web",
                },
            },
        }],
    }
}
