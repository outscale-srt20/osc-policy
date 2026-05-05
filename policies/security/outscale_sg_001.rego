# METADATA
# id: OSC-SG-001
# title: SSH (port 22) ouvert à Internet
# description: |
#   Une règle de security group autorise le port 22 (SSH) depuis 0.0.0.0/0
#   ou ::/0, exposant le service SSH à l'ensemble d'Internet. Cela augmente
#   considérablement la surface d'attaque (brute-force, exploitation 0-day SSH).
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_security_group_rule
# source: plan,live
# remediation: |
#   1. Restreindre l'ip_range à votre CIDR d'administration (ex. 10.0.0.0/8)
#   2. Ou utiliser un bastion dédié et supprimer l'accès SSH direct
#   3. Ou remplacer SSH par SSM/VPN pour l'accès aux instances
# noncompliant_example: |
#   resource "outscale_security_group_rule" "ssh" {
#     flow            = "Inbound"
#     ip_range        = "0.0.0.0/0"
#     ip_protocol     = "tcp"
#     from_port_range = "22"
#     to_port_range   = "22"
#   }
# compliant_example: |
#   resource "outscale_security_group_rule" "ssh" {
#     flow            = "Inbound"
#     ip_range        = "10.0.0.0/8"
#     ip_protocol     = "tcp"
#     from_port_range = "22"
#     to_port_range   = "22"
#   }
# references:
#   - "CIS Benchmark 4.1"
#   - "ANSSI BP-028 R67"
# compliance:
#   anssi_bp_028: ["R65", "R67"]
#   secnumcloud_3_2: ["13.2", "13.3"]
#   cis_controls_v8: ["4.4", "12.2"]
#   iso_27001_2022: ["A.8.20", "A.8.22"]
package security.outscale.sg_001

import rego.v1

import data.lib.modules

_public_cidrs := {"0.0.0.0/0", "::/0"}

deny contains msg if {
    some r in modules.all_resources
    r.type == "outscale_security_group_rule"
    r.values.flow == "Inbound"
    r.values.from_port_range == "22"
    r.values.ip_protocol == "tcp"
    r.values.ip_range in _public_cidrs
    msg := json.marshal({
        "rule_id":          "OSC-SG-001",
        "rule_title":       "SSH (port 22) ouvert à Internet",
        "severity":         "HIGH",
        "category":         "security",
        "resource_id":      r.address,
        "resource_type":    r.type,
        "resource_address": r.address,
        "message":          sprintf("Security group rule %s expose le port SSH 22 à Internet (%s)", [r.address, r.values.ip_range]),
        "remediation":      "Restreindre ip_range à votre CIDR d'administration ou utiliser un bastion.",
    })
}

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_security_group_rule"
    r.values.flow == "Inbound"
    r.values.from_port_range == "22"
    r.values.ip_protocol == "tcp"
    r.values.ip_range in _public_cidrs
    msg := json.marshal({
        "rule_id":          "OSC-SG-001",
        "rule_title":       "SSH (port 22) ouvert à Internet",
        "severity":         "HIGH",
        "category":         "security",
        "resource_id":      object.get(r, "id", r.address),
        "resource_type":    r.type,
        "resource_address": r.address,
        "message":          sprintf("Security group rule expose le port SSH 22 à Internet (%s)", [r.values.ip_range]),
    })
}
