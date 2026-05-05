# METADATA
# id: OSC-LBU-002
# title: Listener HTTP:80 sans redirection HTTPS
# description: |
#   Un listener HTTP:80 doit rediriger vers HTTPS plutôt que servir du contenu
#   en clair.
# severity: MEDIUM
# category: security
# profile: security
# resource_types:
#   - outscale_load_balancer
# source: plan,live
# remediation: |
#   Configurer une règle de redirection 301 HTTP → HTTPS au niveau de
#   l'application, ou désactiver le listener HTTP.
# noncompliant_example: |
#   listeners { load_balancer_port = 80 load_balancer_protocol = "HTTP" }
# compliant_example: |
#   # Redirection 301 configurée au niveau de l'application
# references: []
# compliance:
#   anssi_bp_028: ["R72"]
#   secnumcloud_3_2: ["10.2"]
#   cis_controls_v8: ["3.11"]
#   iso_27001_2022: ["A.8.24"]
package security.outscale.lbu_002

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_lbus
    some l in object.get(r.values, "listeners", [])
    l.load_balancer_protocol == "HTTP"
    l.load_balancer_port == 80
    msg := json.marshal({
        "rule_id": "OSC-LBU-002",
        "rule_title": "Listener HTTP:80 sans redirection HTTPS",
        "severity": "MEDIUM",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "Listener HTTP:80 présent — s'assurer de la redirection 301 vers HTTPS",
        "remediation": "Mettre en place la redirection 301 vers HTTPS.",
    })
}

all_lbus := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_load_balancer"]
    live := [r | some r in modules.live_resources; r.type == "outscale_load_balancer"]
    out := array.concat(plan, live)
}
