# METADATA
# id: OSC-VOL-002
# title: Volume de type standard (déprécié)
# description: |
#   Le type standard (magnétique) est déprécié et offre de faibles performances.
#   Préférer gp2 (SSD général) ou io1 (SSD provisioned IOPS).
# severity: MEDIUM
# category: finops
# profile: finops
# resource_types:
#   - outscale_volume
# source: plan,live
# remediation: |
#   Migrer vers `volume_type = "gp2"`.
# noncompliant_example: |
#   resource "outscale_volume" "v" { volume_type = "standard" size = 100 }
# compliant_example: |
#   resource "outscale_volume" "v" { volume_type = "gp2" size = 100 }
# references: []
# compliance:

#   secnumcloud_3_2: ["8.2"]

#   iso_27001_2022: ["A.5.10"]
package finops.outscale.vol_002

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_vols
    r.values.volume_type == "standard"
    msg := json.marshal({
        "rule_id": "OSC-VOL-002",
        "rule_title": "Volume de type standard (déprécié)",
        "severity": "MEDIUM",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "Volume de type standard déprécié — migrer vers gp2",
        "remediation": "Changer volume_type en gp2.",
    })
}

all_vols := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_volume"]
    live := [r | some r in modules.live_resources; r.type == "outscale_volume"]
    out := array.concat(plan, live)
}
