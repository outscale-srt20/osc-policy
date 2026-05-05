# METADATA
# id: OSC-SG-001
# title: Port sensible ouvert à 0.0.0.0/0
# description: |
#   Une règle de security group autorise le trafic entrant depuis l'Internet
#   public (0.0.0.0/0) sur un port sensible. Cela expose directement le service
#   à des tentatives d'attaque (brute force SSH, exploitation RDP, injection SQL).
# severity: CRITICAL
# category: security
# profile: security
# resource_types:
#   - outscale_security_group_rule
# source: plan,live
# remediation: |
#   1. Identifier la plage IP légitime qui doit accéder à ce port
#   2. Remplacer 0.0.0.0/0 par cette plage restreinte (ex: 10.0.0.0/8)
#   3. Si l'accès doit être public, utiliser un LBU devant les VMs
#   4. Pour SSH, privilégier un bastion ou un VPN Outscale
# noncompliant_example: |
#   resource "outscale_security_group_rule" "ssh" {
#     flow            = "Inbound"
#     ip_range        = "0.0.0.0/0"
#     from_port_range = "22"
#     to_port_range   = "22"
#     ip_protocol     = "tcp"
#   }
# compliant_example: |
#   resource "outscale_security_group_rule" "ssh" {
#     flow            = "Inbound"
#     ip_range        = "10.0.0.0/8"
#     from_port_range = "22"
#     to_port_range   = "22"
#     ip_protocol     = "tcp"
#   }
# references:
#   - "CIS Benchmark 4.1"
#   - "https://docs.outscale.com/en/userguide/Security-Groups.html"
#   - "ANSSI-BP-028 R67"
# compliance:
#   anssi_bp_028: ["R65", "R67"]
#   secnumcloud_3_2: ["13.2", "13.3"]
#   cis_controls_v8: ["4.4", "12.2"]
#   iso_27001_2022: ["A.8.20", "A.8.22"]
#   iso_27017: ["CLD.13.1.4"]
package security.outscale.sg_001

import rego.v1

import data.lib.modules
import data.lib.utils

deny contains msg if {
    some resource in all_sg_rules
    resource.values.flow == "Inbound"
    utils.is_public_cidr(resource.values.ip_range)
    port := resource.values.from_port_range
    sprintf("%v", [port]) in utils.sensitive_ports
    msg := json.marshal({
        "rule_id":         "OSC-SG-001",
        "rule_title":      "Port sensible ouvert à 0.0.0.0/0",
        "severity":        "CRITICAL",
        "category":        "security",
        "resource_id":     object.get(resource, "id", resource.address),
        "resource_type":   resource.type,
        "resource_address": resource.address,
        "message":         sprintf("Port sensible %v ouvert à %v", [port, resource.values.ip_range]),
        "remediation":     "Restreindre le CIDR source au range IP autorisé. Utiliser un bastion ou un VPN plutôt qu'exposer SSH/RDP directement.",
        "references":      ["CIS Benchmark 4.1", "https://docs.outscale.com/en/userguide/Security-Groups.html"],
    })
}

all_sg_rules := out if {
    plan := [r | some r in modules.all_resources; r.type == "outscale_security_group_rule"]
    live := [r | some r in modules.live_resources; r.type == "outscale_security_group_rule"]
    out := array.concat(plan, live)
}
