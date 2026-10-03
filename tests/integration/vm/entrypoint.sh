#!/bin/sh
set -eu
echo "root:${ROOT_PASSWORD}" | chpasswd
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
