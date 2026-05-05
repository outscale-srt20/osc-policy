package security.outscale.eim_009_test

import rego.v1

import data.security.outscale.eim_009

test_policy_with_notaction_fails if {
    count(eim_009.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_eim_policy",
            "id":      "policy-bad",
            "address": "DangerousPolicy",
            "values": {
                "document_body": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"NotAction\":[\"iam:*\"],\"Resource\":\"*\"}]}",
            },
        }],
    }
}

test_policy_with_notresource_fails if {
    count(eim_009.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_eim_policy",
            "id":      "policy-bad-resource",
            "address": "DangerousResource",
            "values": {
                "document_body": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"NotResource\":\"arn:aws:s3:::secret\"}]}",
            },
        }],
    }
}

test_policy_with_action_resource_passes if {
    count(eim_009.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_eim_policy",
            "id":      "policy-good",
            "address": "ReadOnlyPolicy",
            "values": {
                "document_body": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":\"arn:aws:s3:::my-bucket/*\"}]}",
            },
        }],
    }
}

test_empty_policy_passes if {
    count(eim_009.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_eim_policy",
            "id":      "policy-empty",
            "address": "EmptyPolicy",
            "values": {
                "document_body": "",
            },
        }],
    }
}
