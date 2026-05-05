# METADATA
# id: OSC-IMG-001
# title: Image privée non utilisée par aucune VM active
# description: |
#   Une OMI custom créée mais non utilisée par des VMs actives reste
#   facturée pour son stockage de snapshot sous-jacent. Audit régulier
#   recommandé, surtout après les builds Packer.
# severity: LOW
# category: finops
# profile: finops
# resource_types:
#   - outscale_image
# source: live
# remediation: |
#   1. Confirmer qu'aucune CI/CD n'utilise cette image comme base.
#   2. Supprimer via DeleteImage (qui supprime aussi le snapshot sous-jacent).
package finops.outscale.image_unused

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_images
    is_private(r)
    not used_by_vm(r.values.image_id)
    msg := build(r)
}

is_private(r) if {
    r.values.permissions_to_launch.global_permission == false
    r.values.account_alias != "Outscale"
}

used_by_vm(image_id) if {
    some v in modules.resources_of_type("outscale_vm")
    v.values.image_id == image_id
}

build(r) := json.marshal({
    "rule_id": "OSC-IMG-001",
    "rule_title": "OMI privée non utilisée",
    "severity": "LOW",
    "category": "finops",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("OMI '%s' (privée) non utilisée par aucune VM active — stockage snapshot facturé", [r.address]),
    "remediation": "Confirmer absence d'usage CI/CD, puis DeleteImage.",
})

all_images := modules.resources_of_type("outscale_image")
