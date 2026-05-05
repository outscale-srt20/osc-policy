# METADATA
# id: OSC-KEY-002
# title: Access key inactive depuis plus de 90 jours
# description: |
#   Une access key non utilisée depuis plus de 90 jours est suspecte : soit
#   elle n'est plus nécessaire, soit elle est détournée. Elle doit être
#   révoquée ou rotée.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_access_key
# source: live
# remediation: |
#   Désactiver ou supprimer la clé. Mettre en place une politique de rotation.
# noncompliant_example: |
#   # Clé avec last_used_date > 90 jours
# compliant_example: |
#   # Clé récemment utilisée ou désactivée
# references: []
# compliance:
#   anssi_bp_028: ["R11", "R13"]
#   secnumcloud_3_2: ["19.1", "19.3", "19.5"]
#   cis_controls_v8: ["5.3", "5.6"]
#   iso_27001_2022: ["A.5.17", "A.5.18", "A.8.2"]
package security.outscale.key_002

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_access_key"
    age_days := object.get(r.values, "last_used_age_days", 0)
    age_days > 90
    msg := json.marshal({
        "rule_id": "OSC-KEY-002",
        "rule_title": "Access key inactive depuis 90+ jours",
        "severity": "HIGH",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": sprintf("Access key inactive depuis %v jours", [age_days]),
        "remediation": "Révoquer ou roter la clé.",
    })
}
