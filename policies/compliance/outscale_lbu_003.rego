# METADATA
# id: OSC-LBU-003
# title: LBU sans health check configuré
# description: |
#   Sans health check, le LBU continue d'envoyer du trafic à des backends
#   défaillants, provoquant des erreurs côté client.
# severity: MEDIUM
# category: compliance
# profile: compliance
# resource_types:
#   - outscale_load_balancer
# source: plan,live
# remediation: |
#   Configurer `health_check` avec chemin, port, intervalle et seuils sains.
# noncompliant_example: |
#   resource "outscale_load_balancer" "lb" { listeners { ... } }
# compliant_example: |
#   resource "outscale_load_balancer" "lb" {
#     health_check {
#       healthy_threshold   = 2
#       unhealthy_threshold = 2
#       interval            = 10
#       port                = 8080
#       protocol            = "HTTP"
#       path                = "/health"
#     }
#   }
# references: []
# compliance:
#   anssi_bp_028: ["R24"]
#   secnumcloud_3_2: ["12.4"]
#   cis_controls_v8: ["13.1"]
#   iso_27001_2022: ["A.8.14"]
#   iso_27017: ["CLD.12.4.5"]
package compliance.outscale.lbu_003

import rego.v1
import data.lib.modules

deny contains msg if {
    some r in all_lbus
    not r.values.health_check
    msg := build(r)
}
deny contains msg if {
    some r in all_lbus
    r.values.health_check == null
    msg := build(r)
}

build(r) := json.marshal({
    "rule_id": "OSC-LBU-003",
    "rule_title": "LBU sans health check",
    "severity": "MEDIUM",
    "category": "security",
    "resource_id": object.get(r, "id", r.address),
    "resource_type": r.type,
    "resource_address": r.address,
    "message": "Load Balancer sans health check configuré",
    "remediation": "Configurer un health check applicatif.",
})

all_lbus := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_load_balancer"]
    live := [r | some r in modules.live_resources; r.type == "outscale_load_balancer"]
    out := array.concat(plan, live)
}
