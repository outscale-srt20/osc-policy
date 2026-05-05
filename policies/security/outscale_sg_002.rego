# METADATA
# id: OSC-SG-002
# title: All-traffic inbound autorisé (ip_protocol=-1)
# description: |
#   Une règle de security group autorise tout trafic entrant (protocole -1)
#   quel que soit le port, ce qui désactive le filtrage réseau. Cela expose
#   tous les services de la VM/subnet à Internet si le CIDR est public.
# severity: CRITICAL
# category: security
# profile: security
# resource_types:
#   - outscale_security_group_rule
# source: plan,live
# remediation: |
#   1. Supprimer la règle all-traffic
#   2. Créer des règles spécifiques par protocole et par port
#   3. Restreindre les CIDRs aux plages internes uniquement
# noncompliant_example: |
#   resource "outscale_security_group_rule" "all" {
#     flow        = "Inbound"
#     ip_range    = "0.0.0.0/0"
#     ip_protocol = "-1"
#   }
# compliant_example: |
#   resource "outscale_security_group_rule" "https" {
#     flow            = "Inbound"
#     ip_range        = "10.0.0.0/16"
#     ip_protocol     = "tcp"
#     from_port_range = "443"
#     to_port_range   = "443"
#   }
# references:
#   - "CIS Benchmark 4.2"
# compliance:
#   anssi_bp_028: ["R65", "R67"]
#   secnumcloud_3_2: ["13.2", "13.3"]
#   cis_controls_v8: ["4.4", "12.2"]
#   iso_27001_2022: ["A.8.20", "A.8.22"]
package security.outscale.sg_002

import rego.v1

import data.lib.modules

deny contains msg if {
    some r in modules.all_resources
    r.type == "outscale_security_group_rule"
    r.values.flow == "Inbound"
    r.values.ip_protocol == "-1"
    msg := json.marshal({
        "rule_id":          "OSC-SG-002",
        "rule_title":       "All-traffic inbound autorisé (ip_protocol=-1)",
        "severity":         "CRITICAL",
        "category":         "security",
        "resource_id":      r.address,
        "resource_type":    r.type,
        "resource_address": r.address,
        "message":          "Security group rule autorise tout le trafic entrant (ip_protocol=-1)",
        "remediation":      "Remplacer la règle par des règles TCP/UDP ciblées sur les ports nécessaires.",
    })
}

deny contains msg if {
    some r in modules.live_resources
    r.type == "outscale_security_group_rule"
    r.values.flow == "Inbound"
    r.values.ip_protocol == "-1"
    msg := json.marshal({
        "rule_id":          "OSC-SG-002",
        "rule_title":       "All-traffic inbound autorisé (ip_protocol=-1)",
        "severity":         "CRITICAL",
        "category":         "security",
        "resource_id":      object.get(r, "id", r.address),
        "resource_type":    r.type,
        "resource_address": r.address,
        "message":          "Security group rule autorise tout le trafic entrant (ip_protocol=-1)",
    })
}
