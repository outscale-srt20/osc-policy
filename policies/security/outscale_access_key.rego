# METADATA
# id: OSC-KEY-001
# title: Access key sans date d'expiration
# description: |
#   Une access key sans date d'expiration permet un accès permanent au compte.
#   Les bonnes pratiques imposent une rotation régulière (90 jours max).
# severity: CRITICAL
# category: security
# profile: security
# resource_types:
#   - outscale_access_key
# source: plan,live
# remediation: |
#   1. Définir `expiration_date` (ISO 8601)
#   2. Mettre en place une rotation automatique des clés
# noncompliant_example: |
#   resource "outscale_access_key" "k" { user_name = "alice" }
# compliant_example: |
#   resource "outscale_access_key" "k" {
#     user_name       = "alice"
#     expiration_date = "2026-12-31T23:59:59Z"
#   }
# references:
#   - "ANSSI-BP-028 R79"
# compliance:
#   anssi_bp_028: ["R11", "R13"]
#   secnumcloud_3_2: ["19.1", "19.5"]
#   cis_controls_v8: ["5.3", "5.6"]
#   iso_27001_2022: ["A.5.17", "A.8.2"]
package security.outscale.key_001

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_keys
    not r.values.expiration_date
    msg := build(r)
}
deny contains msg if {
    some r in all_keys
    r.values.expiration_date == ""
    msg := build(r)
}

build(r) := json.marshal({
    "rule_id": "OSC-KEY-001",
    "rule_title": "Access key sans expiration",
    "severity": "CRITICAL",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": "Access key créée sans date d'expiration",
    "remediation": "Définir une expiration_date sur l'access key.",
})

all_keys := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_access_key"]
    live := [r | some r in modules.live_resources; r.type == "outscale_access_key"]
    out := array.concat(plan, live)
}
