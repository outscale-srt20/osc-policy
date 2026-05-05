# METADATA
# id: OSC-EIM-008
# title: Policy EIM avec wildcard Resource "*"
# description: |
#   Une policy EIM contient au moins un Statement `Allow` avec une Resource
#   wildcard (`*`). Les actions autorisées s'appliquent alors à **toutes** les
#   ressources du compte, sans possibilité de cantonnement par ORN
#   (projet, environnement, équipe). Combiné à un jeu d'actions large, cela
#   équivaut à une escalade de privilèges implicite.
# severity: HIGH
# category: security
# profile: security
# resource_types:
#   - outscale_eim_policy
# source: live
# remediation: |
#   1. Lister les ORN (OUTSCALE Resource Names) réellement ciblés par les
#      actions du Statement
#   2. Remplacer `"Resource": "*"` par la liste de ces ORN ou un préfixe ORN
#      discriminant (ex: `"orn:ows:kms:eu-west-2:<account>:key/*"`)
#   3. Si l'action est strictement globale (ex: `ReadQuotas`), la documenter
#      explicitement dans la description de la policy pour justifier l'usage
# noncompliant_example: |
#   {
#     "Version": "2012-10-17",
#     "Statement": [
#       {
#         "Effect": "Allow",
#         "Action": ["ReadVolumes", "DeleteVolume"],
#         "Resource": "*"
#       }
#     ]
#   }
# compliant_example: |
#   {
#     "Version": "2012-10-17",
#     "Statement": [
#       {
#         "Effect": "Allow",
#         "Action": ["ReadVolumes", "DeleteVolume"],
#         "Resource": [
#           "orn:ows:api:eu-west-2:123456789012:volume/vol-11111111",
#           "orn:ows:api:eu-west-2:123456789012:volume/vol-22222222"
#         ]
#       }
#     ]
#   }
# references:
#   - "https://docs.outscale.com/en/userguide/Resource-Identifiers.html"
#   - "CIS Controls v8 — 6.8 Least Privilege"
# compliance:
#   anssi_bp_028: ["R13"]
#   secnumcloud_3_2: ["19.1", "19.3"]
#   cis_controls_v8: ["6.7", "6.8"]
#   iso_27001_2022: ["A.5.15", "A.5.18", "A.8.3"]
package security.outscale.eim_008

import rego.v1

import data.lib.modules

deny contains msg if {
	some policy in modules.resources_of_type("outscale_eim_policy")
	some stmt in policy.values.statements
	stmt.effect == "Allow"
	"*" in stmt.resources
	# Ne déclenche pas si OSC-EIM-007 déclenchera déjà (Action * = cas plus grave)
	not "*" in stmt.actions
	msg := json.marshal({
		"rule_id": "OSC-EIM-008",
		"rule_title": "Policy EIM avec wildcard Resource \"*\"",
		"severity": "HIGH",
		"category": "security",
		"resource_id": object.get(policy.values, "policy_id", policy.address),
		"resource_type": policy.type,
		"resource_address": policy.address,
		"message": sprintf(
			"Policy EIM %v contient un Statement Allow avec Resource=\"*\" (toutes les ressources du compte)",
			[policy.address],
		),
		"remediation": "Restreindre Resource aux ORN spécifiques que la policy doit réellement couvrir.",
		"references": [
			"https://docs.outscale.com/en/userguide/Resource-Identifiers.html",
			"CIS Controls v8 — 6.8",
		],
	})
}
