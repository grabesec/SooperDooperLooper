# What happens during a rollover

`sdl rollover run` (or `POST /api/v1/rollovers`, or the web page) selects
systems from the inventory ([inventory.md](inventory.md)) by name, group, or
`--all`, and requires a reason, which goes into the audit log. Up to
`rollover.max_parallel` targets are processed at once, and a target can only
be in one run at a time.

For each target the orchestrator runs these steps, recording each one in the
audit log and in the target's report. Credentials never appear in either.

| Step            | What happens                                                                 | If it fails                         |
|-----------------|------------------------------------------------------------------------------|-------------------------------------|
| `service_account` | Only for systems that name a service account: read its SSH key or password from the secrets module | **failed**, nothing changed        |
| `connect`       | SSH to the VM as the service account, with strict host key checking           | **failed**, nothing changed        |
| `preflight`     | Service account works, account exists, sudo allows `chpasswd`, verifier available | **failed**, nothing changed        |
| `read_previous` | Read the current password from Vault (kept for rollback)                      | **failed**, nothing changed        |
| `generate`      | Generate a new password from the configured policy                            |                                     |
| `escrow`        | Write the new password to `<secret_path>/__sdl_pending` in Vault              | **failed**, nothing changed        |
| `change`        | `sudo -n chpasswd`, password passed on stdin, never on a command line          | see below                           |
| `verify`        | Prove the VM accepts the new password (`su` or a fresh SSH login)              | roll back to the previous password  |
| `store`         | Write the new password to `<secret_path>` in Vault as a new version           | **needs attention**, password is escrowed |
| `cleanup`       | Delete the escrow copy                                                        | logged, run still succeeds          |

`--dry-run` stops after `read_previous`: it proves SDL can reach every VM and
Vault, and that the service account has the rights it needs, without changing
anything.

## Why a password is never lost

The new password is in Vault *before* it is set on the VM. Whatever fails
after that, the password the VM has is always one that Vault holds:

- **`change` fails**: SDL checks which password the VM now accepts. If it is
  the new one (the command applied before the connection dropped), it carries
  on. If it is the old one, the target is reported **failed** and unchanged.
  Otherwise it is **needs attention**, with the escrow path in the message.
- **`verify` fails**: SDL sets the previous password back and verifies it:
  **rolled back**. If there is no previous password (first rollover) or the
  restore fails, it reports **needs attention** with the escrow path.
- **`store` fails**: the VM has the new, verified password and it is still
  escrowed: **needs attention**.

## Result statuses

| Status            | Meaning                                                          |
|-------------------|------------------------------------------------------------------|
| `succeeded`       | New password set, verified and stored                            |
| `checked`         | Dry run passed                                                   |
| `failed`          | Stopped before the change; the VM still has its old password     |
| `rolled_back`     | New password rejected; the previous one was restored and verified |
| `needs_attention` | SDL could not finish safely; the message says where the password is |

A run is `succeeded` when every target succeeded (or was checked), `partial`
when some did, and `failed` when none did. The CLI exits 0 only for
`succeeded`, so it can be scripted.

## Verifying the password

`target.ssh_linux` offers two verifiers:

- **`su`** (default): from the service account's session, `su root` with the
  new password over a pseudo-terminal, and check a marker the command prints.
  Works with `PermitRootLogin no`. It needs a non-root service account (root
  can `su` without a password, which would prove nothing), and fails on hosts
  that restrict `su` with `pam_wheel`.
- **`ssh_login`**: open a new SSH connection as the account with the new
  password. Needs `PasswordAuthentication yes`, and `PermitRootLogin yes` for root.
