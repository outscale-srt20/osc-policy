# METADATA
# id: OSC-VOL-005
# title: Volume > 1 To sans tag large_volume_approved
# description: |
#   Un volume de grande taille (> 1 To) est un coût significatif. On exige
#   que l'équipe Platform ait approuvé explicitement la création, via un
#   tag `large_volume_approved`.
# severity: LOW
# category: security
# profile: security
# resource_types:
#   - outscale_volume
# source: plan,live
# remediation: |
#   Ajouter le tag `large_volume_approved=yes` (avec un ticket référencé)
#   ou réduire la taille.
# noncompliant_example: |
#   resource "outscale_volume" "v" { size = 2000 }
# compliant_example: |
#   resource "outscale_volume" "v" {
#     size = 2000
#     tags { key = "large_volume_approved" value = "TICKET-1234" }
#   }
# references: []
# compliance:
#   secnumcloud_3_2: ["8.2"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.10", "A.8.9"]
package security.outscale.vol_005

import rego.v1
import data.lib.modules
import data.lib.utils

deny contains msg if {
    some r in all_vols
    s := to_number_safe(object.get(r.values, "size", 0))
    s > 1000
    not utils.has_tag(object.get(r.values, "tags", []), "large_volume_approved")
    msg := json.marshal({
        "rule_id": "OSC-VOL-005",
        "rule_title": "Volume > 1 To sans approbation",
        "severity": "LOW",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": sprintf("Volume de %v Go sans tag large_volume_approved", [s]),
        "remediation": "Ajouter le tag large_volume_approved ou réduire la taille.",
    })
}

default to_number_safe(_) := 0
to_number_safe(v) := v if is_number(v)
to_number_safe(v) := to_number(v) if is_string(v)

all_vols := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_volume"]
    live := [r | some r in modules.live_resources; r.type == "outscale_volume"]
    out := array.concat(plan, live)
}
