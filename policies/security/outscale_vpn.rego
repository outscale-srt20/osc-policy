# METADATA
# id: OSC-VPN-001
# title: Connexion VPN sans static_routes_only
# description: |
#   Une connexion VPN en mode BGP partage des routes dynamiques. Dans
#   certains contextes (petites interconnexions, conformité), on préfère
#   imposer static_routes_only=true pour un contrôle explicite.
# severity: MEDIUM
# category: security
# profile: security
# resource_types:
#   - outscale_vpn_connection
# source: plan,live
# remediation: |
#   Activer `static_routes_only = true` et gérer les routes explicitement.
# noncompliant_example: |
#   resource "outscale_vpn_connection" "vpn" { static_routes_only = false }
# compliant_example: |
#   resource "outscale_vpn_connection" "vpn" { static_routes_only = true }
# references: []
# compliance:
#   anssi_bp_028: ["R65", "R72"]
#   secnumcloud_3_2: ["13.1", "13.2"]
#   cis_controls_v8: ["12.2"]
#   iso_27001_2022: ["A.8.20", "A.8.21"]
package security.outscale.vpn_001

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_vpns
    object.get(r.values, "static_routes_only", false) == false
    msg := json.marshal({
        "rule_id": "OSC-VPN-001",
        "rule_title": "VPN sans static_routes_only",
        "severity": "MEDIUM",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "VPN sans static_routes_only=true",
        "remediation": "Activer static_routes_only=true.",
    })
}

all_vpns := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_vpn_connection"]
    live := [r | some r in modules.live_resources; r.type == "outscale_vpn_connection"]
    out := array.concat(plan, live)
}
