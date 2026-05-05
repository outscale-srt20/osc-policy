package finops.outscale.snapshot_old_test

import rego.v1

import data.finops.outscale.snapshot_old

# 100 days in nanoseconds.
old_age_ns := 100 * 24 * 3600 * 1000 * 1000 * 1000

test_old_snapshot_fails if {
    old_date := time.format(time.now_ns() - old_age_ns)
    count(snapshot_old.deny) > 0 with input as {
        "resources": [{
            "type":    "outscale_snapshot",
            "id":      "snap-old",
            "address": "snap-old",
            "values": {
                "creation_date": old_date,
            },
        }],
    }
}

test_recent_snapshot_passes if {
    recent_date := time.format(time.now_ns())
    count(snapshot_old.deny) == 0 with input as {
        "resources": [{
            "type":    "outscale_snapshot",
            "id":      "snap-recent",
            "address": "snap-recent",
            "values": {
                "creation_date": recent_date,
            },
        }],
    }
}
