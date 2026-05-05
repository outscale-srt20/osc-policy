# METADATA
# id: OSC-ACC-003
# title: Aucune règle d'accès API définie
# description: |
#   Le compte Outscale n'a **aucune** règle d'accès API configurée. Les appels
#   à l'API ne sont donc pas restreints par source IP ou par certificat client,
#   ce qui équivaut à exposer la totalité de l'API à toute personne détenant
#   une access key valide.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_api_access_summary
# source: live
# remediation: |
#   1. Définir au moins une `ApiAccessRule` restreignant les `IpRanges` aux
#      plages IP légitimes (VPN, bureaux, CI/CD)
#   2. Si l'authentification par certificat client est déployée, configurer
#      `CaIds` et `Cns`
#   3. Activer `RequireTrustedEnv` dans la policy d'accès API
# noncompliant_example: |
#   # Aucune règle d'accès API : ReadApiAccessRules retourne une liste vide.
# compliant_example: |
#   # Au moins une règle restreignant les sources autorisées :
#   {
#     "ApiAccessRuleId": "aar-xxxxxxxx",
#     "IpRanges": ["198.51.100.0/24"],
#     "Description": "Bureau principal"
#   }
# references:
#   - "https://docs.outscale.com/en/userguide/About-Your-API-Access-Policy.html"
#   - "https://docs.outscale.com/api#readapiaccessrules"
# compliance:
#   anssi_bp_028: ["R65", "R67"]
#   secnumcloud_3_2: ["13.2", "13.3", "19.1"]
#   cis_controls_v8: ["4.4", "12.2"]
#   iso_27001_2022: ["A.5.15", "A.8.2", "A.8.20"]
package security.outscale.acc_003

import rego.v1

import data.lib.modules

deny contains msg if {
	some summary in modules.resources_of_type("outscale_api_access_summary")
	summary.values.rule_count == 0
	msg := json.marshal({
		"rule_id": "OSC-ACC-003",
		"rule_title": "Aucune règle d'accès API définie",
		"severity": "HIGH",
		"category": "security",
		"resource_id": "api-access-summary",
		"resource_type": "outscale_api_access_summary",
		"resource_address": "api-access-summary",
		"message": "Aucune ApiAccessRule définie sur le compte : l'API est accessible depuis n'importe où avec une access key valide.",
		"remediation": "Créer au moins une ApiAccessRule restreignant IpRanges aux plages IP légitimes.",
		"references": [
			"https://docs.outscale.com/en/userguide/About-Your-API-Access-Policy.html",
		],
	})
}
