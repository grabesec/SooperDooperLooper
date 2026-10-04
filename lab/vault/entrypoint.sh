#!/bin/sh
# Vault for the lab: real file storage, so secrets survive a restart (a dev
# server would forget them), unsealed automatically with the one unseal key
# kept next to the data. Fine for a lab, never for anything real: whoever can
# read the lab's Vault volume can unseal it.
set -eu
umask 077
export VAULT_ADDR=http://127.0.0.1:8200
rm -f /tmp/lab-ready
vault server -config=/lab/vault.hcl &
server=$!
trap 'kill -TERM "$server"; wait "$server"' TERM INT

# vault status: 0 unsealed, 2 sealed or not initialized, 1 not answering yet.
until vault status >/dev/null 2>&1 || [ $? -eq 2 ]; do sleep 1; done

# Only the unseal key is kept (mode 600); the initial root token is revoked
# once the lab's own token exists, so it never sits on disk.
keyfile=/vault/file/lab-unseal-key
old=/vault/file/lab-init.txt   # earlier labs kept the root token here too
if [ -s "$old" ] && [ ! -s "$keyfile" ]; then
  vault operator unseal "$(sed -n 's/^Unseal Key 1: //p' "$old")" >/dev/null
  VAULT_TOKEN=$(sed -n 's/^Initial Root Token: //p' "$old") vault token revoke -self >/dev/null 2>&1 || true
  sed -n 's/^Unseal Key 1: //p' "$old" > "$keyfile"
fi
rm -f "$old"
fresh=0
if [ ! -s "$keyfile" ]; then
  init=$(vault operator init -key-shares=1 -key-threshold=1)
  printf '%s\n' "$init" | sed -n 's/^Unseal Key 1: //p' > "$keyfile.tmp"
  mv "$keyfile.tmp" "$keyfile"
  root=$(printf '%s\n' "$init" | sed -n 's/^Initial Root Token: //p')
  unset init
  fresh=1
fi
chmod 600 "$keyfile"
vault operator unseal "$(cat "$keyfile")" >/dev/null

if [ "$fresh" = 1 ]; then
  VAULT_TOKEN="$root" vault secrets enable -path=secret kv-v2 >/dev/null
  VAULT_TOKEN="$root" vault token create -id="$LAB_VAULT_TOKEN" -policy=root -orphan >/dev/null 2>&1
  VAULT_TOKEN="$root" vault token revoke -self >/dev/null
  unset root
  echo "lab: vault initialized; token $LAB_VAULT_TOKEN"
fi
touch /tmp/lab-ready
echo "lab: vault unsealed"
wait "$server"
