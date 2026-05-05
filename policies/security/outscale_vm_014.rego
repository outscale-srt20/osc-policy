# METADATA
# id: OSC-VM-014
# title: VM avec IP publique et security group ouvert à 0.0.0.0/0
# description: |
#   Une VM dispose d'une IP publique **et** d'au moins un security group
#   autorisant du trafic entrant depuis Internet (0.0.0.0/0 ou ::/0).
#   Cette combinaison expose directement la VM aux scanners et aux attaques
#   automatisées : c'est l'un des vecteurs d'intrusion les plus fréquents.
# severity: CRITICAL
# category: security
# profile: security
# resource_types:
#   - outscale_vm
#   - outscale_security_group_rule
# source: live
# remediation: |
#   1. Retirer les règles Inbound avec ip_range = 0.0.0.0/0 du security group
#   2. Restreindre la source à un CIDR autorisé (ex: 10.0.0.0/8)
#   3. Si l'exposition publique est nécessaire, détacher l'IP publique de la
#      VM et passer par un load balancer (LBU) ou un NAT service
#   4. Pour l'administration SSH/RDP, privilégier un bastion ou un VPN
# noncompliant_example: |
#   resource "outscale_public_ip_link" "web" {
#     vm_id     = outscale_vm.web.id
#     public_ip = outscale_public_ip.web.public_ip
#   }
#   resource "outscale_security_group_rule" "ssh_open" {
#     security_group_id = outscale_security_group.web.id
#     flow              = "Inbound"
#     ip_range          = "0.0.0.0/0"   # ← combo dangereux
#     from_port_range   = "22"
#     to_port_range     = "22"
#     ip_protocol       = "tcp"
#   }
# compliant_example: |
#   resource "outscale_security_group_rule" "ssh_restricted" {
#     security_group_id = outscale_security_group.web.id
#     flow              = "Inbound"
#     ip_range          = "10.0.0.0/8"
#     from_port_range   = "22"
#     to_port_range     = "22"
#     ip_protocol       = "tcp"
#   }
# references:
#   - "CIS Benchmark 4.1"
#   - "https://docs.outscale.com/en/userguide/Security-Groups.html"
#   - "ANSSI-BP-028 R67"
# compliance:
#   anssi_bp_028: ["R65", "R67", "R68"]
#   secnumcloud_3_2: ["13.1", "13.2", "13.3"]
#   cis_controls_v8: ["4.4", "12.2"]
#   iso_27001_2022: ["A.8.20", "A.8.22"]
#   iso_27017: ["CLD.9.5.2", "CLD.13.1.4"]
package security.outscale.vm_014

import rego.v1

import data.lib.modules
import data.lib.utils

# Ensemble des security groups qui ont au moins une règle Inbound
# autorisant un CIDR public (0.0.0.0/0 ou ::/0).
exposed_sg_ids contains sg_id if {
	some r in modules.resources_of_type("outscale_security_group_rule")
	r.values.flow == "Inbound"
	utils.is_public_cidr(r.values.ip_range)
	sg_id := r.values.security_group_id
	sg_id != null
	sg_id != ""
}

# VM exposée : a une IP publique ET un SG figurant dans exposed_sg_ids.
deny contains msg if {
	some vm in modules.resources_of_type("outscale_vm")
	has_public_ip(vm)
	some sg_id in vm.values.security_group_ids
	sg_id in exposed_sg_ids
	msg := json.marshal({
		"rule_id": "OSC-VM-014",
		"rule_title": "VM avec IP publique et SG ouvert à 0.0.0.0/0",
		"severity": "CRITICAL",
		"category": "security",
		"resource_id": object.get(vm, "id", vm.address),
		"resource_type": vm.type,
		"resource_address": vm.address,
		"message": sprintf(
			"VM %v exposée publiquement via le security group %v (règle Inbound ouverte à 0.0.0.0/0)",
			[vm.address, sg_id],
		),
		"remediation": "Retirer la règle Inbound 0.0.0.0/0 sur ce SG, ou détacher l'IP publique et passer par un LBU.",
		"references": [
			"CIS Benchmark 4.1",
			"https://docs.outscale.com/en/userguide/Security-Groups.html",
		],
	})
}

# has_public_ip — true si la VM porte une IP publique, directement ou via
# une ressource outscale_public_ip liée par vm_id.
has_public_ip(vm) if {
	ip := vm.values.public_ip
	is_string(ip)
	ip != ""
}

has_public_ip(vm) if {
	some pip in modules.resources_of_type("outscale_public_ip")
	pip.values.vm_id == object.get(vm.values, "id", "")
	pip.values.vm_id != ""
}

has_public_ip(vm) if {
	some pip in modules.resources_of_type("outscale_public_ip")
	pip.values.vm_id == vm.address
}
