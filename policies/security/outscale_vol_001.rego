# METADATA
# id: OSC-VOL-001
# title: Volume io1 sans iops explicite
# description: |
#   Un volume de type io1 (provisioned IOPS) sans paramètre iops explicite
#   peut recevoir un ratio iops/size imprévisible, entraînant sur-facturation
#   ou sous-performance.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_volume
# source: plan,live
# remediation: |
#   Définir explicitement `iops` en fonction du besoin (max 300 IOPS/Go).
# noncompliant_example: |
#   resource "outscale_volume" "v" { volume_type = "io1" size = 100 }
# compliant_example: |
#   resource "outscale_volume" "v" { volume_type = "io1" size = 100 iops = 3000 }
# references: []
# compliance:
#   secnumcloud_3_2: ["20.1"]
#   cis_controls_v8: ["4.8"]
#   iso_27001_2022: ["A.8.9"]
package security.outscale.vol_001

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_vols
    r.values.volume_type == "io1"
    not r.values.iops
    msg := build(r, "Volume io1 sans iops explicite")
}

build(r, m) := json.marshal({
    "rule_id": "OSC-VOL-001",
    "rule_title": "Volume io1 sans iops explicite",
    "severity": "HIGH",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": m,
    "remediation": "Spécifier le paramètre iops sur le volume io1.",
})

all_vols := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_volume"]
    live := [r | some r in modules.live_resources; r.type == "outscale_volume"]
    out := array.concat(plan, live)
}
