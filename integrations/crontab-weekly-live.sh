#!/usr/bin/env bash
# Weekly live scan of an Outscale account, archiving HTML/JSON reports
# in OOS for trend analysis.
#
# Crontab example (every Monday at 03:00):
#   0 3 * * 1 /opt/osc-policy/integrations/crontab-weekly-live.sh
#
# Required:
#   - osc-policy in PATH
#   - ~/.osc/config.json (or env OUTSCALE_ACCESSKEYID/SECRETKEYID)
#   - aws-cli configured to write to OOS_BUCKET
# Optional:
#   - SLACK_WEBHOOK_URL : will send a summary if set

set -euo pipefail

OOS_BUCKET="${OOS_BUCKET:-osc-policy-reports}"
OOS_ENDPOINT="${OOS_ENDPOINT:-https://oos.eu-west-2.outscale.com}"
DATE=$(date +%Y-%m-%d)
WORKDIR=$(mktemp -d)
cd "$WORKDIR"

echo "→ Running osc-policy live scan ($DATE)..."
osc-policy scan live --severity LOW --output json     --output-file "scan-$DATE.json"
osc-policy scan live --severity LOW --output markdown --output-file "scan-$DATE.md"

echo "→ Uploading reports to s3://$OOS_BUCKET/weekly/..."
aws s3 cp "scan-$DATE.json" "s3://$OOS_BUCKET/weekly/scan-$DATE.json" --endpoint-url "$OOS_ENDPOINT"
aws s3 cp "scan-$DATE.md"   "s3://$OOS_BUCKET/weekly/scan-$DATE.md"   --endpoint-url "$OOS_ENDPOINT"

if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
    bash "$(dirname "$0")/slack-webhook.sh" "scan-$DATE.json" "Weekly scan ($DATE)"
fi

echo "✓ Weekly scan complete."
rm -rf "$WORKDIR"
