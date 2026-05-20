#!/usr/bin/env bash
set -eo pipefail

export STEPPATH=/home/step
KUBE_CLIENT_CA_KEY_PATH=$STEPPATH/kube-api-secrets/kube_apiserver_client_ca_key
KUBE_CLIENT_CA_CRT_PATH=$STEPPATH/kube-api-secrets/kube_apiserver_client_ca.crt

main() {
  printf "Creating CA config\n" >&2
  : "${DNSNAMES:?}"
  jq --arg nodenames "$DNSNAMES" --argjson admin_keys "$(cat /home/step/admin-keys.json)" '
    .dnsNames+=($nodenames | split(",") | unique) |
    .authority.provisioners+=[$admin_keys[] |
      {
       "type": "JWK",
       "name": .kid,
       "key": .,
       "options": { "x509": { "templateFile": "/home/step/admin.tpl" } },
      }
    ]' "$STEPPATH/k8sss.json" >"$STEPPATH/config/ca.json"

  local certs_ram_path=$STEPPATH/secrets
  printf "Copying kubernetes client CA cert & key to RAM backed volume\n" >&2
  cp "$KUBE_CLIENT_CA_CRT_PATH" "$certs_ram_path/$(basename "$KUBE_CLIENT_CA_CRT_PATH")"
  cp "$KUBE_CLIENT_CA_KEY_PATH" "$certs_ram_path/$(basename "$KUBE_CLIENT_CA_KEY_PATH")"
  chown 1000:1000 "$certs_ram_path/$(basename "$KUBE_CLIENT_CA_CRT_PATH")"
  chown 1000:1000 "$certs_ram_path/$(basename "$KUBE_CLIENT_CA_KEY_PATH")"
}

main "$@"
