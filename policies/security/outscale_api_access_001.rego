# METADATA
# id: OSC-ACC-001
# title: Règle d'accès API trop large (CIDR public)
# description: |
#   Une règle d'accès API (`ApiAccessRule`) autorise des appels à l'API Outscale
#   depuis un CIDR public (`0.0.0.0/0` ou `::/0`). Cela signifie que toute
#   personne disposant d'une access key valide peut appeler l'API depuis
#   n'importe où sur Internet, ce qui annule l'effet de cantonnement réseau.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_api_access_rule
# source: live
# remediation: |
#   1. Identifier les plages IP légitimes (VPN, bureaux, plateformes CI/CD)
#   2. Restreindre les `IpRanges` de la règle à ces seules plages
#   3. Supprimer toute règle autorisant `0.0.0.0/0` ou `::/0`
#   4. Durcir en activant `RequireTrustedEnv` dans la policy d'accès API
# noncompliant_example: |
#   # API Outscale — règle d'accès API trop permissive
#   {
#     "ApiAccessRuleId": "aar-xxxxxxxx",
#     "IpRanges": ["0.0.0.0/0"]
#   }
# compliant_example: |
#   {
#     "ApiAccessRuleId": "aar-xxxxxxxx",
#     "IpRanges": ["198.51.100.0/24", "203.0.113.0/24"]
#   }
# references:
#   - "https://docs.outscale.com/en/userguide/About-Your-API-Access-Policy.html"
#   - "https://docs.outscale.com/api#readapiaccessrules"
# compliance:
#   anssi_bp_028: ["R65", "R67"]
#   secnumcloud_3_2: ["13.2", "13.3", "19.1"]
#   cis_controls_v8: ["4.4", "12.2"]
#   iso_27001_2022: ["A.5.15", "A.8.2", "A.8.20"]
package security.outscale.acc_001

import rego.v1

import data.lib.modules
import data.lib.utils

deny contains msg if {
	some rule in modules.resources_of_type("outscale_api_access_rule")
	some cidr in rule.values.ip_ranges
	utils.is_public_cidr(cidr)
	msg := json.marshal({
		"rule_id": "OSC-ACC-001",
		"rule_title": "Règle d'accès API trop large (CIDR public)",
		"severity": "HIGH",
		"category": "security",
		"resource_id": object.get(rule.values, "api_access_rule_id", rule.address),
		"resource_type": rule.type,
		"resource_address": rule.address,
		"message": sprintf(
			"Règle d'accès API %v autorise les appels depuis %v (CIDR public)",
			[rule.address, cidr],
		),
		"remediation": "Restreindre IpRanges aux plages IP légitimes ; supprimer toute règle ouverte à 0.0.0.0/0 ou ::/0.",
		"references": [
			"https://docs.outscale.com/en/userguide/About-Your-API-Access-Policy.html",
		],
	})
}
