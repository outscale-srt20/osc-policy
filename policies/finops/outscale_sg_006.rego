# METADATA
# id: OSC-SG-006
# title: Security group orphelin (non attaché)
# description: |
#   Un security group non attaché à une VM ou NIC est un artefact inutile,
#   potentiellement résidu d'un déploiement ancien. Risque: une VM future
#   pourrait être attachée par erreur à un SG permissif oublié.
# severity: MEDIUM
# category: finops
# profile: finops
# resource_types:
#   - outscale_security_group
# source: live
# remediation: |
#   1. Vérifier qu'aucune automatisation ne l'utilise
#   2. Supprimer le security group via l'API ou Terraform
# noncompliant_example: |
#   # SG existant dans l'API mais non référencé par aucune ressource
# compliant_example: |
#   resource "outscale_vm" "web" {
#     security_group_ids = [outscale_security_group.web.id]
#   }
# references: []
# compliance:
#   secnumcloud_3_2: ["8.1", "8.2"]
#   cis_controls_v8: ["1.1"]
#   iso_27001_2022: ["A.5.9", "A.5.10"]
package finops.outscale.sg_006

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_security_group"
    object.get(r, "attached", true) == false
    msg := json.marshal({
        "rule_id":          "OSC-SG-006",
        "rule_title":       "Security group orphelin",
        "severity":         "MEDIUM",
        "category":         "security",
        "resource_id":      object.get(r, "id", r.address),
        "resource_type":    r.type,
        "resource_address": r.address,
        "message":          "Security group non attaché à une VM ou NIC",
        "remediation":      "Supprimer ou ré-attribuer le security group.",
    })
}
