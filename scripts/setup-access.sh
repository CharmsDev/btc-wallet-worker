#!/usr/bin/env bash
# Create a self-hosted Access application that accepts only service tokens.
# Requires CF_API_TOKEN, CF_ACCOUNT_ID, and APP_DOMAIN. Prints the application
# AUD tag and, when it creates one, a service token. Nothing is written to disk.
set -euo pipefail

: "${CF_API_TOKEN:?set CF_API_TOKEN}"
: "${CF_ACCOUNT_ID:?set CF_ACCOUNT_ID}"
: "${APP_DOMAIN:?set APP_DOMAIN to the worker hostname, for example wallet.example.com}"

app_name="${APP_NAME:-satchel}"
api="https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}"

python_post() {
  local url="$1"
  local payload="$2"
  curl --silent --show-error --fail \
    --request POST \
    --header "Authorization: Bearer ${CF_API_TOKEN}" \
    --header "Content-Type: application/json" \
    --data "$payload" \
    "$url"
}

app_payload="$(APP_NAME="$app_name" APP_DOMAIN="$APP_DOMAIN" python3 - <<'PY'
import json, os
print(json.dumps({
    "name": os.environ["APP_NAME"],
    "domain": os.environ["APP_DOMAIN"],
    "type": "self_hosted",
    "session_duration": "24h",
    "auto_redirect_to_identity": False,
    "policies": [{
        "name": "Service tokens only",
        "decision": "non_identity",
        "precedence": 1,
        "include": [{"any_valid_service_token": {}}],
    }],
}))
PY
)"

app_json="$(python_post "${api}/access/apps" "$app_payload")"
python3 - "$app_json" <<'PY'
import json, sys
body = json.loads(sys.argv[1])
if not body.get("success"):
    raise SystemExit(json.dumps(body.get("errors", body)))
result = body["result"]
print(f"access_app_id={result.get('id', '')}")
print(f"aud={result.get('aud', '')}")
print("Set ACCESS_AUD to the aud value and ACCESS_TEAM_DOMAIN to your team name.")
PY

token_json="$(python_post "${api}/access/service_tokens" "$(python3 - <<'PY'
import json
print(json.dumps({"name": "satchel-agent", "duration": "8760h"}))
PY
)")"
python3 - "$token_json" <<'PY'
import json, sys
body = json.loads(sys.argv[1])
if not body.get("success"):
    raise SystemExit(json.dumps(body.get("errors", body)))
result = body["result"]
print(f"cf_access_client_id={result.get('client_id', '')}")
print(f"cf_access_client_secret={result.get('client_secret', '')}")
print("Store the client secret now. Cloudflare will not show it again.")
PY
