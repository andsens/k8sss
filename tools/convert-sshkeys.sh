#!/usr/bin/env bash



main() {
  local ssh_key admin_jwk jwks='[]'
  while IFS= read -r -d $'\n' ssh_key || [[ -n $ssh_key ]]; do
    admin_jwk=$(step crypto key format --jwk <<<"$ssh_key")
    jwks=$(jq \
      --arg kid "$(step crypto jwk thumbprint <<<"$admin_jwk")" \
      --argjson jwk "$admin_jwk" \
      '.+=[($jwk | .kid=$kid)]' \
      <<<"$jwks"
    )
  done < <(cat "$1")
  printf "%s\n" "$jwks"
}

main "$@"
