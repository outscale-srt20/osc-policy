# METADATA
# id: OSC-LBU-004
# title: LBU sans access_log activé
# description: |
#   Sans access_log, aucune trace des requêtes traitées par le LBU. En cas
#   d'incident (DDoS, scrap, attaque applicative), pas de forensic possible.
#   Activer access_log avec écriture dans un bucket OOS de durée de
#   rétention adaptée.
# severity: MEDIUM
# category: security
# profile: security
# resource_types:
#   - outscale_load_balancer
# source: plan,live
# remediation: |
#   Configurer un outscale_load_balancer_attributes avec access_log :
#     access_log {
#       is_enabled           = true
#       osu_bucket_name      = "lbu-access-logs"
#       osu_bucket_prefix    = "<lbu-name>/"
#       publication_interval = 5
#     }
# compliance:
#   anssi_bp_028: ["R75"]
#   secnumcloud_3_2: ["12.4.1"]
#   cis_controls_v8: ["8.2", "8.5"]
#   iso_27001_2022: ["A.8.15", "A.8.16"]
package security.outscale.lbu_004

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_lbus
    not access_log_enabled(r)
    msg := build(r)
}

access_log_enabled(r) if {
    r.values.access_log.is_enabled == true
}

build(r) := json.marshal({
    "rule_id": "OSC-LBU-004",
    "rule_title": "LBU sans access_log activé",
    "severity": "MEDIUM",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": sprintf("Load Balancer '%s' sans access_log activé — pas de forensic possible", [r.address]),
    "remediation": "Activer access_log via outscale_load_balancer_attributes (bucket OOS dédié, rétention configurée).",
})

all_lbus := modules.resources_of_type("outscale_load_balancer")
