# METADATA
# id: OSC-OOS-003
# title: Bucket OOS sans tag Name
# description: |
#   Pas de tag Name → difficile d'identifier l'usage du bucket lors des audits
#   de facturation.
# severity: MEDIUM
# category: security
# profile: security
# resource_types:
#   - outscale_oos
# source: live
# remediation: |
#   Ajouter un tag Name explicite au bucket.
# noncompliant_example: |
#   # Bucket sans tag Name
# compliant_example: |
#   # Bucket avec tag Name=logs-prod
# references: []
# compliance:
#   anssi_bp_028: ["R1"]
#   secnumcloud_3_2: ["8.1"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.9"]
package security.outscale.oos_003

import rego.v1
import data.lib.modules
import data.lib.utils

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_oos"
    not utils.has_tag(object.get(r.values, "tags", []), "Name")
    msg := json.marshal({
        "rule_id": "OSC-OOS-003",
        "rule_title": "Bucket OOS sans tag Name",
        "severity": "MEDIUM",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "Bucket OOS sans tag Name",
        "remediation": "Ajouter un tag Name explicite.",
    })
}
