# METADATA
# id: OSC-NET-004
# title: Internet Service orphelin (non rattaché à un Net)
# description: |
#   Un Internet Service Gateway créé mais non lié à un Net (LinkInternetService
#   absent) est inutilisable. Souvent vestige d'une suppression incomplète.
# severity: MEDIUM
# category: finops
# profile: finops
# resource_types:
#   - outscale_internet_service
# source: live
# remediation: |
#   1. Vérifier que l'IGW n'est pas en cours de bascule (création/destruction
#      d'un Net en cours).
#   2. Supprimer via DeleteInternetService.
package finops.outscale.internet_service_004

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_igws
    is_orphan(r)
    msg := build(r)
}

is_orphan(r) if {
    not r.values.net_id
}
is_orphan(r) if {
    r.values.net_id == ""
}

build(r) := json.marshal({
    "rule_id": "OSC-NET-004",
    "rule_title": "Internet Service orphelin",
    "severity": "MEDIUM",
    "category": "finops",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Internet Service '%s' n'est rattaché à aucun Net — inutilisable", [r.address]),
    "remediation": "Vérifier l'absence d'usage, puis DeleteInternetService.",
})

all_igws := modules.resources_of_type("outscale_internet_service")
