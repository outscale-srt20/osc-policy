# METADATA
# id: OSC-OOS-002
# title: Bucket OOS sans versioning
# description: |
#   Sans versioning, la suppression ou l'écrasement d'un objet est définitif.
#   Le versioning protège contre les suppressions accidentelles et les
#   attaques ransomware.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_oos
# source: live
# remediation: |
#   Activer le versioning sur le bucket via PutBucketVersioning.
# noncompliant_example: |
#   # Bucket sans versioning
# compliant_example: |
#   # Bucket avec versioning=Enabled
# references: []
# compliance:
#   secnumcloud_3_2: ["18.1"]
#   cis_controls_v8: ["11.2", "11.3"]
#   iso_27001_2022: ["A.8.13"]
package security.outscale.oos_002

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_oos"
    object.get(r.values, "versioning", "") != "Enabled"
    msg := json.marshal({
        "rule_id": "OSC-OOS-002",
        "rule_title": "Bucket OOS sans versioning",
        "severity": "HIGH",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "Bucket OOS sans versioning activé",
        "remediation": "Activer PutBucketVersioning.",
    })
}
