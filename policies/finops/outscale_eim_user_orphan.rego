# METADATA
# id: OSC-EIM-011
# title: Utilisateur EIM sans aucune access key (orphelin / inactif)
# description: |
#   Un utilisateur EIM créé mais sans access key associée n'a aucun moyen
#   d'utiliser l'API. Soit l'utilisateur a été abandonné après suppression
#   de ses clés (à supprimer pour réduire la surface), soit le provisioning
#   est incomplet. Audit régulier recommandé.
# severity: LOW
# category: finops
# profile: finops
# resource_types:
#   - outscale_eim_user
# source: live
# remediation: |
#   1. Confirmer que l'utilisateur n'est pas en cours d'onboarding ou de
#      réinitialisation de clé.
#   2. Si abandonné : DeleteUser (après avoir détaché les groupes/policies).
package finops.outscale.eim_user_orphan

import rego.v1
import data.lib.modules

deny contains msg if {
    some u in all_users
    not has_keys(u)
    msg := build(u)
}

# Cross-resource: check if any access_key references this user.
has_keys(u) if {
    some k in modules.resources_of_type("outscale_access_key")
    k.values.user_name == u.values.user_name
}

build(u) := json.marshal({
    "rule_id": "OSC-EIM-011",
    "rule_title": "Utilisateur EIM sans aucune access key",
    "severity": "LOW",
    "category": "finops",
    "resource_id": object.get(u, "id", u.address),
    "resource_type": u.type,
    "resource_address": u.address,
    "message": sprintf("Utilisateur EIM '%s' n'a aucune access key — orphelin ou onboarding incomplet", [u.address]),
    "remediation": "Confirmer le statut de l'utilisateur, puis DeleteUser si abandonné.",
})

all_users := modules.resources_of_type("outscale_eim_user")
