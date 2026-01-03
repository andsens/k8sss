#!/usr/bin/env bash
set -eo pipefail

export STEPPATH=/home/step
KUBE_CLIENT_CA_KEY_PATH=$STEPPATH/kube-api-secrets/kube_apiserver_client_ca_key
KUBE_CLIENT_CA_CRT_PATH=$STEPPATH/kube-api-secrets/kube_apiserver_client_ca.crt

main() {
  local config
  printf "Creating CA config\n" >&2
  : "${NODENAME:?}"
  config=$(jq \
    --arg fqnodename "${NODENAME%'.local'}.local" \
    --arg uqnodename "${NODENAME%'.local'}" '
      .dnsNames+=([$uqnodename, $nodename, $ipv4] | unique)
    ' "$STEPPATH/config-ro/kube-client-ca.json")
  config=$(setup_authorized_keys "$config")

  printf "%s\n" "$config" >"$STEPPATH/config/ca.json"

  local certs_ram_path=$STEPPATH/secrets
  printf "Copying kube-client-ca cert & key to RAM backed volume\n" >&2
  cp "$KUBE_CLIENT_CA_CRT_PATH" "$certs_ram_path/$(basename "$KUBE_CLIENT_CA_CRT_PATH")"
  cp "$KUBE_CLIENT_CA_KEY_PATH" "$certs_ram_path/$(basename "$KUBE_CLIENT_CA_KEY_PATH")"
  chown 1000:1000 "$certs_ram_path/$(basename "$KUBE_CLIENT_CA_CRT_PATH")"
  chown 1000:1000 "$certs_ram_path/$(basename "$KUBE_CLIENT_CA_KEY_PATH")"
}

setup_authorized_keys() {
  local config=$1
  # This part is built for converting from authorized_keys format to JWK
  local admin_key admin_jwk
  while IFS= read -r -d $'\n' admin_key || [[ -n $admin_key ]]; do
    admin_jwk=$(step crypto key format --jwk <<<"$admin_key")
    admin_jwk=$(jq --arg kid "$(step crypto jwk thumbprint <<<"$admin_jwk")" '.kid=$kid' <<<"$admin_jwk")
    config=$(jq --argjson key "$admin_jwk" '.authority.provisioners += [{
      "type": "JWK",
      "name": $key.kid,
      "key": $key,
      "options": { "x509": { "templateFile": "/home/step/templates/admin.tpl" } },
    }]' <<<"$config")
  done </home/step/admin_keys
}

main "$@"
