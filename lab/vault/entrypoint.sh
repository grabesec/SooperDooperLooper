#!/bin/sh
# Vault for the lab: real file storage, so secrets survive a restart (a dev
# server would forget them), unsealed automatically with the one unseal key
# kept next to the data. Fine for a lab, never for anything real.
set -eu
export VAULT_ADDR=http://127.0.0.1:8200
rm -f /tmp/lab-ready
vault server -config=/lab/vault.hcl &
server=$!
trap 'kill -TERM "$server"; wait "$server"' TERM INT

# vault status: 0 unsealed, 2 sealed or not initialized, 1 not answering yet.
until vault status >/dev/null 2>&1 || [ $? -eq 2 ]; do sleep 1; done

init=/vault/file/lab-init.txt
fresh=0
if [ ! -s "$init" ]; then
  vault operator init -key-shares=1 -key-threshold=1 > "$init.tmp"
  mv "$init.tmp" "$init"
  fresh=1
fi
vault operator unseal "$(sed -n 's/^Unseal Key 1: //p' "$init")" >/dev/null

if [ "$fresh" = 1 ]; then
  VAULT_TOKEN=$(sed -n 's/^Initial Root Token: //p' "$init") \
    vault secrets enable -path=secret kv-v2 >/dev/null
  VAULT_TOKEN=$(sed -n 's/^Initial Root Token: //p' "$init") \
    vault token create -id="$LAB_VAULT_TOKEN" -policy=root -orphan >/dev/null 2>&1
  echo "lab: vault initialized; token $LAB_VAULT_TOKEN"
fi
touch /tmp/lab-ready
echo "lab: vault unsealed"
wait "$server"
