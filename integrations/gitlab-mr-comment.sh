#!/usr/bin/env bash
# Post osc-policy findings as a comment on the current GitLab MR.
# To be run inside a GitLab CI job after `osc-policy scan plan ... --output json`.
#
# Required env vars (provided by GitLab CI):
#   CI_PROJECT_ID            - numeric project ID
#   CI_MERGE_REQUEST_IID     - MR iid (only in merge_request_event pipeline)
#   CI_API_V4_URL            - https://gitlab.example.com/api/v4
#   GITLAB_TOKEN             - personal/project access token with `api` scope
#                              (set as a protected, masked CI/CD variable)
#
# Usage in .gitlab-ci.yml:
#   script:
#     - osc-policy scan plan plan.json --output json --output-file scan.json
#     - bash integrations/gitlab-mr-comment.sh scan.json

set -euo pipefail

SCAN_JSON="${1:-scan.json}"

if [[ -z "${CI_MERGE_REQUEST_IID:-}" ]]; then
    echo "Not in a merge request pipeline (CI_MERGE_REQUEST_IID empty), skip."
    exit 0
fi

if [[ ! -f "$SCAN_JSON" ]]; then
    echo "Scan file $SCAN_JSON not found"
    exit 1
fi

# Build a markdown summary of CRITICAL + HIGH findings.
COMMENT=$(jq -r '
    [.findings[]? | select(.status == "FAILED") | select(.severity == "CRITICAL" or .severity == "HIGH")] as $high |
    if ($high | length) == 0 then
        "✅ **osc-policy** — aucun finding CRITICAL/HIGH dans ce plan."
    else
        "## 🔍 osc-policy findings (CRITICAL + HIGH)\n\n" +
        "| Sév | Rule | Ressource | Message |\n" +
        "|---|---|---|---|\n" +
        ($high | map(
            "| " + .severity +
            " | `" + .rule_id + "` | `" + (.resource_id // "-") + "` | " +
            (.message | gsub("\\|"; "\\|") | .[0:120]) +
            " |"
        ) | join("\n")) +
        "\n\n_Détail : `osc-policy explain <rule>` ou `osc-policy fix --rule <rule> --resource <id>`._"
    end
' "$SCAN_JSON")

# Post the comment via GitLab API
curl --silent --fail --request POST \
    --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
    --header "Content-Type: application/json" \
    --data "$(jq -nc --arg body "$COMMENT" '{body: $body}')" \
    "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/merge_requests/${CI_MERGE_REQUEST_IID}/notes" \
    > /dev/null

echo "✓ osc-policy comment posted on MR !${CI_MERGE_REQUEST_IID}"
