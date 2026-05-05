# METADATA
# id: OSC-EIM-007
# title: Policy EIM avec wildcard Action "*"
# description: |
#   Une policy EIM contient au moins un Statement `Allow` avec une Action
#   wildcard (`*`). Cela accorde toutes les permissions disponibles à toute
#   entité liée à cette policy — utilisateurs, groupes ou access keys — ce
#   qui viole strictement le principe de moindre privilège.
# severity: CRITICAL
# category: security
# profile: security
# resource_types:
#   - outscale_eim_policy
# source: live
# remediation: |
#   1. Identifier les actions EIM réellement nécessaires aux entités qui
#      utilisent cette policy
#   2. Remplacer `"Action": "*"` par la liste exhaustive des actions requises
#   3. En cas de doute, activer `RequireTrustedEnv` et surveiller les appels
#      Unauthorized via ReadApiLogs pour affiner le scope
# noncompliant_example: |
#   {
#     "Version": "2012-10-17",
#     "Statement": [
#       {
#         "Effect": "Allow",
#         "Action": "*",
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
#         "Action": [
#           "ReadVms",
#           "ReadVolumes",
#           "ReadSnapshots"
#         ],
#         "Resource": "*"
#       }
#     ]
#   }
# references:
#   - "https://docs.outscale.com/en/userguide/EIM-Reference-Information.html"
#   - "https://docs.outscale.com/en/userguide/EIM-Policy-Generator.html"
#   - "CIS Controls v8 — 6.8 Least Privilege"
# compliance:
#   anssi_bp_028: ["R13", "R10"]
#   secnumcloud_3_2: ["19.1", "19.3"]
#   cis_controls_v8: ["6.7", "6.8"]
#   iso_27001_2022: ["A.5.15", "A.5.18", "A.8.2", "A.8.3"]
package security.outscale.eim_007

import rego.v1

import data.lib.modules

deny contains msg if {
	some policy in modules.resources_of_type("outscale_eim_policy")
	some stmt in policy.values.statements
	stmt.effect == "Allow"
	"*" in stmt.actions
	msg := json.marshal({
		"rule_id": "OSC-EIM-007",
		"rule_title": "Policy EIM avec wildcard Action \"*\"",
		"severity": "CRITICAL",
		"category": "security",
		"resource_id": object.get(policy.values, "policy_id", policy.address),
		"resource_type": policy.type,
		"resource_address": policy.address,
		"message": sprintf(
			"Policy EIM %v contient un Statement Allow avec Action=\"*\" (toutes les actions autorisées)",
			[policy.address],
		),
		"remediation": "Remplacer Action=\"*\" par la liste exhaustive des actions réellement nécessaires (principe de moindre privilège).",
		"references": [
			"https://docs.outscale.com/en/userguide/EIM-Reference-Information.html",
			"CIS Controls v8 — 6.8",
		],
	})
}
