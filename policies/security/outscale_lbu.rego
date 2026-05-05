# METADATA
# id: OSC-LBU-001
# title: LBU internet-facing sans listener HTTPS/SSL
# description: |
#   Un Load Balancer exposé sur Internet qui n'a que des listeners HTTP/TCP
#   transmet le trafic en clair, exposant les données et les cookies de session.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_load_balancer
# source: plan,live
# remediation: |
#   Configurer un listener HTTPS (port 443) avec un certificat SSL valide,
#   et rediriger les requêtes HTTP vers HTTPS.
# noncompliant_example: |
#   resource "outscale_load_balancer" "lb" {
#     load_balancer_type = "internet-facing"
#     listeners {
#       load_balancer_port = 80
#       backend_port       = 8080
#       load_balancer_protocol = "HTTP"
#     }
#   }
# compliant_example: |
#   resource "outscale_load_balancer" "lb" {
#     load_balancer_type = "internet-facing"
#     listeners {
#       load_balancer_port = 443
#       backend_port       = 8080
#       load_balancer_protocol = "HTTPS"
#       server_certificate_id  = "arn:..."
#     }
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R72"]
#   secnumcloud_3_2: ["10.2", "13.1"]
#   cis_controls_v8: ["3.11", "16.11"]
#   iso_27001_2022: ["A.8.24", "A.8.21"]
package security.outscale.lbu_001

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_lbus
    r.values.load_balancer_type == "internet-facing"
    listeners := object.get(r.values, "listeners", [])
    not has_https(listeners)
    msg := json.marshal({
        "rule_id": "OSC-LBU-001",
        "rule_title": "LBU internet-facing sans HTTPS",
        "severity": "HIGH",
        "category": "security",
        "resource_id": object.get(r, "id", r.address),
        "resource_type": r.type,
        "resource_address": r.address,
        "message": "Load Balancer public sans listener HTTPS/SSL",
        "remediation": "Ajouter un listener HTTPS avec un certificat.",
    })
}

has_https(listeners) if {
    some l in listeners
    l.load_balancer_protocol == "HTTPS"
}
has_https(listeners) if {
    some l in listeners
    l.load_balancer_protocol == "SSL"
}

all_lbus := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_load_balancer"]
    live := [r | some r in modules.live_resources; r.type == "outscale_load_balancer"]
    out := array.concat(plan, live)
}
