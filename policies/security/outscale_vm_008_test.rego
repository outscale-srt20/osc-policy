package security.outscale.vm_008_test

import rego.v1

import data.security.outscale.vm_008

# Test fixtures below intentionally contain detector-trigger patterns
# (AKIA*, BEGIN PRIVATE KEY, password=...). They are NOT real credentials —
# the test verifies that our detector matches them. This file is excluded
# from secret scanners via .trufflehogignore.

test_user_data_with_aws_access_key_fails if {
    count(vm_008.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_vm",
            "id":      "i-001",
            "address": "outscale_vm.bad",
            "values": {
                # AKIA + 16 chars = format-valid but obviously fake (REPLACEME pattern)
                "user_data": "export OSC_ACCESS_KEY=AKIAREPLACEME0000000",
            },
        }],
    }
}

test_user_data_with_private_key_fails if {
    count(vm_008.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_vm",
            "id":      "i-002",
            "address": "outscale_vm.bad2",
            "values": {
                "user_data": "-----BEGIN RSA PRIVATE KEY-----\n<test-fixture-not-a-real-key>",
            },
        }],
    }
}

test_user_data_with_password_fails if {
    count(vm_008.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_vm",
            "id":      "i-003",
            "address": "outscale_vm.bad3",
            "values": {
                "user_data": "PASSWORD=replace-me-fixture-string",
            },
        }],
    }
}

test_user_data_clean_passes if {
    count(vm_008.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_vm",
            "id":      "i-004",
            "address": "outscale_vm.good",
            "values": {
                "user_data": "#!/bin/bash\napt-get install -y nginx",
            },
        }],
    }
}

test_no_user_data_passes if {
    count(vm_008.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_vm",
            "id":      "i-005",
            "address": "outscale_vm.empty",
            "values": {
                "user_data": "",
            },
        }],
    }
}
