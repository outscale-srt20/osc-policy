# METADATA
# id: OSC-FIN-007
# title: LBU sans backend attaché (orphelin)
# description: |
#   Un Load Balancer sans VM backend est facturé mais ne sert à rien.
#   Cas typique : VMs supprimées sans nettoyer le LBU correspondant.
# severity: MEDIUM
# category: finops
# profile: finops
# resource_types:
#   - outscale_load_balancer
# source: live
# remediation: |
#   1. Vérifier qu'aucun déploiement en cours n'utilise ce LBU.
#   2. Supprimer via DeleteLoadBalancer ou retirer du Terraform.
package finops.outscale.lbu_orphan

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_lbus
    is_orphan(r)
    msg := build(r)
}

is_orphan(r) if {
    not r.values.backend_vm_ids
}
is_orphan(r) if {
    count(r.values.backend_vm_ids) == 0
}

build(r) := json.marshal({
    "rule_id": "OSC-FIN-007",
    "rule_title": "LBU sans backend attaché",
    "severity": "MEDIUM",
    "category": "finops",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Load Balancer '%s' n'a aucune VM backend — facturé sans utilité", [r.address]),
    "remediation": "Vérifier l'absence d'usage actuel, puis DeleteLoadBalancer ou retirer du Terraform.",
})

all_lbus := modules.resources_of_type("outscale_load_balancer")
