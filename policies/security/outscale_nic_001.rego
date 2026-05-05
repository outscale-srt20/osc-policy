# METADATA
# id: OSC-NIC-001
# title: NIC orphelin (non attaché à une VM)
# description: |
#   Une NIC créée mais jamais attachée à une VM (ou détachée sans être
#   supprimée) reste facturée et augmente la surface d'attaque (peut être
#   ré-attachée à une VM sans audit). Nettoyer périodiquement.
# severity: MEDIUM
# category: finops
# profile: finops
# resource_types:
#   - outscale_nic
# source: live
# remediation: |
#   1. Vérifier que la NIC n'est pas en cours d'utilisation (changement
#      en cours, migration de VM).
#   2. Supprimer via DeleteNic ou retirer de la config Terraform.
# compliance:
#   iso_27001_2022: ["A.5.9", "A.8.10"]
package finops.outscale.nic_001

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_nics
    is_orphan(r)
    msg := build(r)
}

is_orphan(r) if {
    not r.values.link_nic
}
is_orphan(r) if {
    link := r.values.link_nic
    is_object(link)
    object.get(link, "vm_id", "") == ""
}

build(r) := json.marshal({
    "rule_id": "OSC-NIC-001",
    "rule_title": "NIC orphelin (non attaché)",
    "severity": "MEDIUM",
    "category": "finops",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("NIC '%s' n'est attachée à aucune VM — facturation continue, surface d'attaque", [r.address]),
    "remediation": "Vérifier qu'aucune VM n'utilise cette NIC, puis DeleteNic ou retirer du Terraform.",
})

all_nics := modules.resources_of_type("outscale_nic")
