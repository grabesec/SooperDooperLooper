#!/bin/sh
set -eu
# The manual QA lab hands over SDL's public key as a file that SDL writes when it starts.
if [ -n "${SDL_PUBKEY_FILE:-}" ]; then
  echo "waiting for ${SDL_PUBKEY_FILE}"
  while [ ! -s "${SDL_PUBKEY_FILE}" ]; do sleep 1; done
  SDL_PUBKEY=$(cat "${SDL_PUBKEY_FILE}")
fi
# Only on first start, so a password SDL rolled over survives a container restart.
if [ ! -e /etc/sdl-test-initialized ]; then
  echo "root:${ROOT_PASSWORD}" | chpasswd
  touch /etc/sdl-test-initialized
fi
install -d -m 700 -o sdl-svc -g sdl-svc /home/sdl-svc/.ssh
printf '%s\n' "${SDL_PUBKEY}" > /home/sdl-svc/.ssh/authorized_keys
chown sdl-svc:sdl-svc /home/sdl-svc/.ssh/authorized_keys
chmod 600 /home/sdl-svc/.ssh/authorized_keys
if [ "${SDL_SUDO:-1}" = "1" ]; then
  echo 'sdl-svc ALL=(root) NOPASSWD: /usr/sbin/chpasswd' > /etc/sudoers.d/sdl-svc
  chmod 440 /etc/sudoers.d/sdl-svc
fi
ssh-keygen -A >/dev/null
exec /usr/sbin/sshd -D -e
