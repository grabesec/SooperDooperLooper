"""Rolls over a local account password on Linux hosts over SSH.

SDL signs in with a dedicated service account, changes the password with
``chpasswd`` through sudo, and verifies the new password by authenticating as
the account with ``su`` (or a fresh SSH password login).

The service account is either the one in this module's configuration (a key
file on the SDL server) or, per system, the ``service_account`` the inventory
names, whose SSH key or password SDL reads from a secrets module.

Recommended sudoers entry for the service account, which grants nothing
except changing passwords::

    sdl-svc ALL=(root) NOPASSWD: /usr/sbin/chpasswd
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
from pathlib import Path
from typing import Any, Literal

import asyncssh
from pydantic import Field, SecretStr

from sdl.core.models import ServiceCredential, TargetSpec
from sdl.core.module import ModuleConfig, ModuleError, TargetModule, TargetSession

_ACCOUNT_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}\$?$", re.I)
_VERIFY_MARKER = "SDL-VERIFY-OK"
# The marker is assembled by printf on the target so it never appears in the
# command line itself; seeing it in the output means the command really ran.
_VERIFY_COMMAND = "printf 'SDL%sOK\\n' -VERIFY-"


class SshLinuxConfig(ModuleConfig):
    username: str | None = Field(
        default=None,
        description="Default SSH service account, for systems that do not name their own.",
    )
    private_key_path: Path | None = Field(
        default=None, description="Private key for the default service account."
    )
    private_key_passphrase_env: str | None = Field(
        default=None, description="Env var holding the private key's passphrase, if any."
    )
    known_hosts_path: Path | None = Field(
        default=None, description="known_hosts file; defaults to ~/.ssh/known_hosts."
    )
    host_key_checking: bool = Field(
        default=True, description="Verify host keys. Turning this off allows MITM attacks."
    )
    connect_timeout: float = 15.0
    command_timeout: float = 30.0
    use_sudo: bool = Field(default=True, description="Run chpasswd through sudo -n.")
    chpasswd_path: str = "/usr/sbin/chpasswd"
    su_path: str = "su"
    verify_method: Literal["su", "ssh_login"] = Field(
        default="su",
        description=(
            "'su': authenticate as the account with su from the service account session. "
            "'ssh_login': open a new SSH connection as the account with the password "
            "(needs PasswordAuthentication, and PermitRootLogin yes for root)."
        ),
    )


class SshLinuxTargetModule(TargetModule):
    Config = SshLinuxConfig
    description = "Changes Linux account passwords over SSH with chpasswd and verifies them."
    config: SshLinuxConfig

    def _known_hosts(self) -> Any:
        if not self.config.host_key_checking:
            return None
        if self.config.known_hosts_path is not None:
            return str(self.config.known_hosts_path)
        return ()  # asyncssh default: ~/.ssh/known_hosts

    def _passphrase(self) -> str | None:
        if self.config.private_key_passphrase_env:
            return os.environ.get(self.config.private_key_passphrase_env)
        return None

    def _client_key(self, path: Path) -> Any:
        try:
            return asyncssh.read_private_key(str(path), self._passphrase())
        except (OSError, asyncssh.KeyImportError) as exc:
            raise ModuleError(f"cannot load private key {path}: {exc}") from exc

    def _login(self, credential: ServiceCredential | None) -> tuple[str, dict[str, Any]]:
        """The service account's username and the asyncssh options to sign in with it."""
        if credential is not None:
            if credential.credential_type == "password":
                return credential.username, {
                    "password": credential.secret.get_secret_value(),
                    "client_keys": None,
                    "preferred_auth": "password,keyboard-interactive",
                }
            try:
                key = asyncssh.import_private_key(
                    credential.secret.get_secret_value(), self._passphrase()
                )
            except (asyncssh.KeyImportError, ValueError) as exc:
                raise ModuleError(
                    f"the SSH key stored for service account {credential.username!r} "
                    f"cannot be loaded: {exc}"
                ) from exc
            return credential.username, {"client_keys": [key], "password": None}
        if self.config.username is None or self.config.private_key_path is None:
            raise ModuleError(
                "no service account: give the system a service_account, or set username and "
                f"private_key_path in the {self.instance_id!r} module configuration"
            )
        return self.config.username, {
            "client_keys": [self._client_key(self.config.private_key_path)],
            "password": None,
        }

    async def open_session(
        self, target: TargetSpec, credential: ServiceCredential | None = None
    ) -> TargetSession:
        if not _ACCOUNT_RE.match(target.account):
            raise ModuleError(f"invalid account name {target.account!r}")
        username, login = self._login(credential)
        try:
            conn = await asyncio.wait_for(
                asyncssh.connect(
                    target.host,
                    port=target.port,
                    username=username,
                    known_hosts=self._known_hosts(),
                    agent_path=None,
                    connect_timeout=self.config.connect_timeout,
                    **login,
                ),
                self.config.connect_timeout + 5,
            )
        except asyncssh.HostKeyNotVerifiable as exc:
            raise ModuleError(f"host key for {target.host} is not trusted: {exc}") from exc
        except asyncssh.PermissionDenied as exc:
            raise ModuleError(f"{target.host} rejected the service account {username!r}") from exc
        except (OSError, asyncssh.Error, TimeoutError) as exc:
            raise ModuleError(f"cannot connect to {target.host}:{target.port}: {exc}") from exc
        return SshLinuxSession(self, target, conn, username)


class SshLinuxSession(TargetSession):
    def __init__(
        self,
        module: SshLinuxTargetModule,
        target: TargetSpec,
        conn: asyncssh.SSHClientConnection,
        username: str,
    ) -> None:
        self.module = module
        self.config = module.config
        self.target = target
        self.conn = conn
        self.username = username

    async def close(self) -> None:
        self.conn.close()
        await self.conn.wait_closed()

    async def _run(self, command: str, stdin: str | None = None) -> asyncssh.SSHCompletedProcess:
        try:
            return await asyncio.wait_for(
                self.conn.run(command, input=stdin, check=False),
                self.config.command_timeout,
            )
        except TimeoutError as exc:
            raise ModuleError(f"command timed out after {self.config.command_timeout}s") from exc

    def _chpasswd_command(self) -> str:
        chpasswd = shlex.quote(self.config.chpasswd_path)
        return f"sudo -n {chpasswd}" if self.config.use_sudo else chpasswd

    async def preflight(self) -> list[str]:
        notes: list[str] = []
        result = await self._run("id -u")
        if result.exit_status != 0:
            raise ModuleError("could not run commands as the service account")
        service_uid = str(result.stdout).strip()
        notes.append(f"signed in as {self.username} (uid {service_uid})")

        result = await self._run(f"getent passwd {shlex.quote(self.target.account)}")
        if result.exit_status != 0:
            raise ModuleError(f"account {self.target.account!r} does not exist on the host")

        if self.config.use_sudo:
            result = await self._run(f"sudo -n -l {shlex.quote(self.config.chpasswd_path)}")
            if result.exit_status != 0:
                raise ModuleError(
                    f"{self.username} may not run {self.config.chpasswd_path} with "
                    "passwordless sudo"
                )
            notes.append(f"sudo allows {self.config.chpasswd_path}")
        elif service_uid != "0":
            raise ModuleError("use_sudo is off but the service account is not root")

        if self.config.verify_method == "su":
            if service_uid == "0":
                raise ModuleError(
                    "verify_method 'su' cannot prove anything when the service account is root "
                    "(root can su without a password); use a non-root service account or "
                    "verify_method 'ssh_login'"
                )
            result = await self._run(f"command -v {shlex.quote(self.config.su_path)}")
            if result.exit_status != 0:
                raise ModuleError(f"{self.config.su_path} is not available on the host")
        notes.append(f"verification by {self.config.verify_method}")
        return notes

    async def set_credential(self, value: SecretStr) -> None:
        password = value.get_secret_value()
        if "\n" in password or "\r" in password:
            raise ModuleError("password must not contain line breaks")
        result = await self._run(
            self._chpasswd_command(), stdin=f"{self.target.account}:{password}\n"
        )
        if result.exit_status != 0:
            stderr = _scrub(str(result.stderr or "").strip(), password)
            raise ModuleError(f"chpasswd exited with {result.exit_status}: {stderr or 'no output'}")

    async def verify_credential(self, value: SecretStr) -> bool:
        if self.config.verify_method == "ssh_login":
            return await self._verify_ssh_login(value)
        return await self._verify_su(value)

    async def _verify_su(self, value: SecretStr) -> bool:
        password = value.get_secret_value()
        command = (
            f"LC_ALL=C LANG=C {shlex.quote(self.config.su_path)} "
            f"{shlex.quote(self.target.account)} -c {shlex.quote(_VERIFY_COMMAND)}"
        )

        async def converse() -> tuple[str, int | None]:
            # su only reads the password from a terminal, so ask for a pty.
            async with self.conn.create_process(command, term_type="dumb") as process:
                output = ""
                while ":" not in output:
                    chunk = await process.stdout.read(1024)
                    if not chunk:
                        break
                    output += chunk
                if ":" in output:
                    process.stdin.write(password + "\n")
                output += await process.stdout.read()
                await process.wait()
                return output, process.exit_status

        try:
            output, status = await asyncio.wait_for(converse(), self.config.command_timeout)
        except TimeoutError as exc:
            raise ModuleError("su did not finish in time") from exc
        return status == 0 and _VERIFY_MARKER in output

    async def _verify_ssh_login(self, value: SecretStr) -> bool:
        try:
            conn = await asyncio.wait_for(
                asyncssh.connect(
                    self.target.host,
                    port=self.target.port,
                    username=self.target.account,
                    password=value.get_secret_value(),
                    client_keys=None,
                    agent_path=None,
                    known_hosts=self.module._known_hosts(),
                    preferred_auth="password,keyboard-interactive",
                    connect_timeout=self.config.connect_timeout,
                ),
                self.config.connect_timeout + 5,
            )
        except asyncssh.PermissionDenied:
            return False
        except (OSError, asyncssh.Error, TimeoutError) as exc:
            raise ModuleError(f"password login to {self.target.host} failed: {exc}") from exc
        try:
            result = await asyncio.wait_for(
                conn.run(_VERIFY_COMMAND, check=False), self.config.command_timeout
            )
            return result.exit_status == 0 and _VERIFY_MARKER in str(result.stdout)
        finally:
            conn.close()
            await conn.wait_closed()


def _scrub(text: str, secret: str) -> str:
    return text.replace(secret, "[redacted]") if secret else text
