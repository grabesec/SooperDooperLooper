#!/usr/bin/env bash
# SDL manual QA lab. Needs Docker with the compose plugin; nothing else on the host.
# See docs/manual-qa.md for what to test.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose=(docker compose -f "$here/docker-compose.yml")
sdl_port="${LAB_SDL_PORT:-8800}"
vault_port="${LAB_VAULT_PORT:-8200}"
sink_port="${LAB_SINK_PORT:-8900}"

usage() {
  cat <<EOF
Usage: ./lab/lab.sh <command>

  up                   build and start the lab, wait until it is ready
  down                 stop the lab, keeping its state (Vault, audit log, inventory)
  reset                throw away all state and start fresh
  destroy              stop the lab and delete all its state
  status               show the lab's containers
  sdl [--as ROLE] ...  run the sdl CLI in the lab (ROLE: admin [default], operator, auditor)
  password SYSTEM      print the root password Vault holds for web1, web2, db1 or app1
  root-login SYSTEM    check root can sign in to that system with Vault's password
  totp USER|KEY        print the current authenticator code of olga or ivan, or for
                       a key the web page shows when setting up an authenticator
  logs [SERVICE]       follow the logs of sdl (default), vault, sink, ldap, vm1 ... vm4
  stop SERVICE         stop one part (vault, sink, ldap, vm2, ...) to test failures
  start SERVICE        start it again
  smoke                run a quick automated check of the lab
EOF
}

exec_flags() {
  # Interactive commands (sdl rollover run -i) need a TTY; scripts and CI have none.
  if [ -t 0 ] && [ -t 1 ]; then echo "-it"; else echo "-T"; fi
}

summary() {
  cat <<EOF

SDL lab is ready.

  Web page   http://127.0.0.1:${sdl_port}/ui/   sign in as a user or with a token below
  API docs   http://127.0.0.1:${sdl_port}/docs
  Vault UI   http://127.0.0.1:${vault_port}/ui/  token: sdl-lab-root
  Log sink   http://127.0.0.1:${sink_port}/       what SDL forwarded to syslog, Graylog, Splunk

  Superuser  sdladmin / lab-superuser-password
  Users      olga   / web-operator-pass   operator of web1, web2   code: ./lab/lab.sh totp olga
             ivan   / auditor-lab-pass    auditor, every system    code: ./lab/lab.sh totp ivan
             newbie / temporary-password  operator of app1; first sign-in sets a new
                                          password and an authenticator
  Directory  alice (admin), bob (web operator), carol (auditor), dave (no access)
             password ldap-password; pick "Lab directory (LDAP)" when signing in
  Tokens     admin-token, operator-token, auditor-token   (API tokens, as before)

  Systems    web1 (vm1)  web2 (vm2)  db1 (vm3, no sudo rule: fails on purpose)  app1 (vm4)
  VMs        ssh -p 2221..2224 root@127.0.0.1   (root password: ./lab/lab.sh password web1)

  CLI        ./lab/lab.sh sdl systems list
             ./lab/lab.sh sdl --as operator rollover run -i --reason "manual QA"

Checklist: docs/manual-qa.md
EOF
}

wait_ready() {
  printf 'Waiting for the lab to be ready'
  for _ in $(seq 1 120); do
    if "${compose[@]}" exec -T sdl python /opt/lab/labctl.py ready 2>/dev/null; then
      echo
      return 0
    fi
    printf '.'
    sleep 3
  done
  echo
  echo "The lab did not get ready. Last SDL logs:" >&2
  "${compose[@]}" logs --tail 40 sdl >&2
  return 1
}

cmd="${1:-help}"
[ $# -gt 0 ] && shift

case "$cmd" in
  up)
    "${compose[@]}" up -d --build
    wait_ready
    summary
    ;;
  down)
    "${compose[@]}" down
    ;;
  reset)
    "${compose[@]}" down -v --remove-orphans
    "${compose[@]}" up -d --build --force-recreate
    wait_ready
    summary
    ;;
  destroy)
    "${compose[@]}" down -v --remove-orphans
    ;;
  status)
    "${compose[@]}" ps
    ;;
  sdl)
    role=admin
    if [ "${1:-}" = "--as" ]; then
      role="${2:?--as needs a role: admin, operator or auditor}"
      shift 2
    fi
    case "$role" in
      admin | operator | auditor) ;;
      *) echo "unknown role $role (admin, operator, auditor)" >&2; exit 2 ;;
    esac
    exec "${compose[@]}" exec $(exec_flags) -e SDL_TOKEN="$role-token" sdl sdl "$@"
    ;;
  totp)
    exec "${compose[@]}" exec -T sdl python /opt/lab/labctl.py totp "${*:?which user? olga or ivan, or a key}"
    ;;
  password | root-login)
    exec "${compose[@]}" exec -T sdl python /opt/lab/labctl.py "$cmd" "${1:?which system? web1, web2, db1 or app1}"
    ;;
  smoke)
    exec "${compose[@]}" exec -T sdl python /opt/lab/labctl.py smoke
    ;;
  logs)
    exec "${compose[@]}" logs -f "${1:-sdl}"
    ;;
  stop | start)
    exec "${compose[@]}" "$cmd" "${1:?which part? vault, sink, vm1 ... vm4, sdl}"
    ;;
  help | -h | --help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
