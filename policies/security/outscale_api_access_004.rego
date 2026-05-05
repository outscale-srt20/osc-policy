# METADATA
# id: OSC-ACC-004
# title: API Access Policy sans rotation forcée des access keys
# description: |
#   La policy d'accès API (ApiAccessPolicy) peut imposer une rotation
#   maximum des access keys via max_access_key_expiration_seconds. Sans
#   cette contrainte, des access keys peuvent rester valides indéfiniment.
# severity: MEDIUM
# category: security
# profile: security
# resource_types:
#   - outscale_api_access_policy
# source: live
# remediation: |
#   Configurer la policy d'accès API avec :
#     max_access_key_expiration_seconds = 7776000  # 90 jours
#   Combiné avec OSC-KEY-001 (expiration_date par clé) pour défense en
#   profondeur.
# compliance:
#   anssi_bp_028: ["R79"]
#   secnumcloud_3_2: ["19.5"]
#   cis_controls_v8: ["5.6"]
package security.outscale.api_access_004

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_policies
    not has_max_expiration(r)
    msg := build(r)
}

has_max_expiration(r) if {
    val := r.values.max_access_key_expiration_seconds
    is_number(val)
    val > 0
}

build(r) := json.marshal({
    "rule_id": "OSC-ACC-004",
    "rule_title": "API Access Policy sans rotation forcée",
    "severity": "MEDIUM",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": "API Access Policy ne force aucune expiration max sur les access keys",
    "remediation": "Configurer max_access_key_expiration_seconds (90 jours = 7776000 typique).",
})

all_policies := modules.resources_of_type("outscale_api_access_policy")
