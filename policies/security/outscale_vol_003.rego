# METADATA
# id: OSC-VOL-003
# title: Volume orphelin (non attaché)
# description: |
#   Un volume BSU non attaché à une VM génère du coût sans usage.
#   Il est probablement résidu d'une VM supprimée.
# severity: MEDIUM
# category: security
# profile: security
# resource_types:
#   - outscale_volume
# source: live
# remediation: |
#   Supprimer le volume ou l'attacher à une VM légitime après vérification.
# noncompliant_example: |
#   # Volume state=available depuis longtemps sans attachement
# compliant_example: |
#   # Volume attaché à une VM
# references: []
# compliance:
#   secnumcloud_3_2: ["8.1", "8.2"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.9", "A.5.10"]
package security.outscale.vol_003

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_volume"
    r.values.state == "available"
    count(object.get(r.values, "linked_volumes", [])) == 0
    msg := json.marshal({
        "rule_id": "OSC-VOL-003",
        "rule_title": "Volume orphelin",
        "severity": "MEDIUM",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "Volume BSU non attaché à une VM",
        "remediation": "Supprimer le volume ou l'attacher à une VM.",
    })
}
