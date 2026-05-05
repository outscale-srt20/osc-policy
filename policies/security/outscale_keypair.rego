# METADATA
# id: OSC-KP-001
# title: Keypair non utilisée par aucune VM
# description: |
#   Une keypair non référencée est un risque si sa clé privée a fuité, et
#   un artefact obsolète.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_keypair
# source: live
# remediation: |
#   Supprimer la keypair ou l'attacher à une VM.
# noncompliant_example: |
#   # Keypair existante mais non référencée
# compliant_example: |
#   resource "outscale_vm" "v" { keypair_name = outscale_keypair.k.keypair_name }
# references: []
# compliance:
#   secnumcloud_3_2: ["8.1", "19.5"]
#   cis_controls_v8: ["1.1", "5.3"]
#   iso_27001_2022: ["A.5.9", "A.5.17"]
package security.outscale.kp_001

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_keypair"
    object.get(r, "in_use", false) == false
    msg := json.marshal({
        "rule_id": "OSC-KP-001",
        "rule_title": "Keypair inutilisée",
        "severity": "HIGH",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "Keypair non utilisée par aucune VM",
        "remediation": "Supprimer la keypair ou l'attacher à une VM.",
    })
}
