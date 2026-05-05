#!/bin/sh
# Plumber audit - requires GITLAB_TOKEN; silently skipped if absent.
if [ -z "$GITLAB_TOKEN" ]; then
  echo "plumber: GITLAB_TOKEN absent, audit ignoré"
  exit 0
fi
exec plumber analyze --threshold 100
