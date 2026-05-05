#!/usr/bin/env bash
# Send a summary of an osc-policy scan to a Slack channel via webhook.
#
# Required env vars:
#   SLACK_WEBHOOK_URL   - https://hooks.slack.com/services/...
#
# Usage:
#   osc-policy scan live --output json --output-file scan.json
#   bash integrations/slack-webhook.sh scan.json [optional-context]

set -euo pipefail

SCAN_JSON="${1:-scan.json}"
CONTEXT="${2:-osc-policy nightly scan}"

if [[ -z "${SLACK_WEBHOOK_URL:-}" ]]; then
    echo "SLACK_WEBHOOK_URL is empty"
    exit 1
fi

# Aggregate counts
counts=$(jq '{
    critical: ([.findings[]? | select(.status == "FAILED") | select(.severity == "CRITICAL")] | length),
    high:     ([.findings[]? | select(.status == "FAILED") | select(.severity == "HIGH")]     | length),
    medium:   ([.findings[]? | select(.status == "FAILED") | select(.severity == "MEDIUM")]   | length),
    low:      ([.findings[]? | select(.status == "FAILED") | select(.severity == "LOW")]      | length),
    grade:    (.score.grade // "?")
}' "$SCAN_JSON")

CRIT=$(jq -r '.critical' <<< "$counts")
HIGH=$(jq -r '.high'     <<< "$counts")
MED=$(jq -r '.medium'    <<< "$counts")
LOW=$(jq -r '.low'       <<< "$counts")
GRADE=$(jq -r '.grade'   <<< "$counts")

# Pick an emoji based on the worst severity
if   [[ $CRIT -gt 0 ]]; then EMOJI=":rotating_light:"; COLOR="#dc3545"
elif [[ $HIGH -gt 0 ]]; then EMOJI=":warning:";        COLOR="#fd7e14"
elif [[ $MED  -gt 0 ]]; then EMOJI=":large_yellow_circle:"; COLOR="#ffc107"
else                         EMOJI=":white_check_mark:";    COLOR="#28a745"
fi

# Top 3 critiques as bullet lines
TOP3=$(jq -r '
    [.findings[]? | select(.status == "FAILED")]
    | sort_by(if .severity == "CRITICAL" then 0 elif .severity == "HIGH" then 1 elif .severity == "MEDIUM" then 2 else 3 end)
    | .[0:3]
    | map("• *" + .severity + "* `" + .rule_id + "` " + (.resource_id // "-") + " — " + (.message | .[0:100]))
    | join("\n")
' "$SCAN_JSON")

PAYLOAD=$(jq -nc \
    --arg emoji "$EMOJI" --arg color "$COLOR" \
    --arg ctx "$CONTEXT" --arg grade "$GRADE" \
    --argjson crit "$CRIT" --argjson high "$HIGH" --argjson med "$MED" --argjson low "$LOW" \
    --arg top "$TOP3" \
    '{
        text: ($emoji + " " + $ctx + " — Grade " + $grade),
        attachments: [{
            color: $color,
            fields: [
                {title: "CRITICAL", value: ($crit|tostring), short: true},
                {title: "HIGH",     value: ($high|tostring), short: true},
                {title: "MEDIUM",   value: ($med|tostring),  short: true},
                {title: "LOW",      value: ($low|tostring),  short: true}
            ],
            text: $top
        }]
    }')

curl --silent --fail \
    --header "Content-Type: application/json" \
    --request POST \
    --data "$PAYLOAD" \
    "$SLACK_WEBHOOK_URL" > /dev/null

echo "✓ Slack notification sent (CRITICAL=$CRIT HIGH=$HIGH MEDIUM=$MED LOW=$LOW)"
