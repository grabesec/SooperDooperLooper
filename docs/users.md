# Users, sign-in and access

Who may use SDL, how they prove it, and which systems each person reaches.

| Who                                 | Signs in with                                    | Kept in                          |
|-------------------------------------|--------------------------------------------------|----------------------------------|
| The **superuser**                   | name + password (+ optional TOTP)                | its own file (`identity.superuser_file`) |
| **Local users**                     | name + password (+ TOTP)                         | the user-store module (`users.store`) |
| **Directory users** (AD, LDAP)      | their directory name + password, checked by the directory (+ optional SDL TOTP) | the directory; SDL keeps a record |
| **Single sign-on users** (Entra ID, Okta, Keycloak, Google, AD FS...) | the provider's own sign-in page (OpenID Connect or SAML) | the provider; SDL keeps a record |
| **Machine clients** (scripts, CI)   | an API token                                      | `auth.static_token` in `sdl.yaml` |

Everyone gets two things:

- **roles**, which say *what* they may do:

  | Role       | May                                                              |
  |------------|------------------------------------------------------------------|
  | `admin`    | everything: rollovers, inventory, audit log, modules, users      |
  | `operator` | run and read rollovers, list systems                             |
  | `auditor`  | read rollovers, list systems, read the audit log, list users     |

- **access**, which says *where*: whole inventory **groups**, individual
  **systems**, or **every system**. A user only sees, rolls over, and reads
  the log of the systems they reach. Asking for a system outside it answers
  "unknown system", so its name is not even confirmed. The log shows such a
  user the events about their systems and their own actions.

## The superuser

The superuser exists before anything else is configured, so an administrator
can always sign in, add users and recover from a broken directory. Create it
on the SDL server, as the system account SDL runs as:

```bash
sdl superuser set -f /etc/sdl/superuser.json --name sdladmin          # asks for the password
sdl superuser set -f /etc/sdl/superuser.json --keep-password --totp   # add an authenticator app
```

```yaml
identity:
  superuser_file: /etc/sdl/superuser.json
```

- The file holds the name and an **Argon2id hash** of the password, never the
  password. It is written with mode `600`; SDL refuses to start when the file
  is missing, readable by other system users, or owned by someone else.
- SDL reads it at every sign-in, so `sdl superuser set` resets the password
  without a restart, and ends the superuser's open sessions.
- The superuser has the `superuser` role (every permission, every system).
  Nobody else can be given that role or take that name, and the superuser
  cannot sign in through a directory.
- Use it to set things up and for emergencies; give people their own accounts.

## Local users

```yaml
modules:
  users:
    type: users.store
    config:
      path: /var/lib/sdl/users.json     # mode 600, like the superuser file
identity:
  password_min_length: 12
  require_mfa: true                     # local users must set up TOTP
```

```bash
sdl login -u sdladmin                                 # session kept in ~/.config/sdl/session.json
sdl users add olga --role operator --group web --system db1      # asks for an initial password
sdl users set olga --add-group prod --remove-system db1
sdl users set olga --disable                         # takes effect at once
sdl users password olga                               # temporary; she must change it
sdl users reset-mfa olga                              # lost phone
sdl users unlock olga                                 # after too many failed sign-ins
sdl users list
```

Or on the web page, in the **Users** section.

- A password set by an administrator is temporary: at first sign-in the user
  can do nothing but choose a new one (`sdl passwd`, or the page asks).
- With `require_mfa`, a user without an authenticator can do nothing but set
  one up (`sdl mfa setup`, or the page shows the key and a link for the phone).
  Codes are standard TOTP (RFC 6238, 6 digits, 30 seconds): any authenticator
  app works. A code is accepted once only.
- After `max_failed_logins` failures in a row (default 5) the name is locked
  for `lockout` seconds (default 15 minutes), or until an administrator unlocks
  it. Unknown names and wrong passwords get the same answer, after the same
  delay.
- Changing someone's password, authenticator, or disabling or removing them
  ends their open sessions. Changes to roles, groups and systems apply to their
  very next request.
- Only someone who reaches every system can add or change users, so a person
  limited to some systems cannot widen their own reach.

## Directories and single sign-on

Identity providers are modules of kind `idp`. Each maps the provider's groups
to SDL roles and access:

```yaml
    group_mapping:
      - group: SDL-Admins          # a name, an LDAP DN, or an Entra ID group object id
        roles: [admin]
        all_systems: true
      - group: Web-Operators
        roles: [operator]
        groups: [web]              # SDL inventory groups
        systems: [db1]             # and/or single systems
    default_roles: []              # roles everyone from this provider gets
    provision: true                # keep a record of each user at first sign-in
```

A user whose groups map to no role cannot sign in. On first sign-in SDL keeps
a record of the user (`provision`), so administrators see them in the user
list, can **disable** them in SDL, and can give them **extra** roles, groups
and systems on top of what their groups grant (`sdl users set`). Directory
users can also be added ahead of their first sign-in:

```bash
sdl idps                                   # configured providers
sdl users search ad "smith"                # look people up in the directory
sdl users import ad jsmith --role auditor --group db
```

Removing a directory user only removes SDL's record: with `provision`, they
get a new one at their next sign-in. To keep someone out, **disable** them.

A name that already belongs to another source (a local user, another
provider) is refused rather than merged.

### Active Directory and LDAP (`idp.ldap`)

```yaml
  ad:
    type: idp.ldap
    config:
      display_name: Contoso AD
      directory: active_directory          # or generic (OpenLDAP, 389 DS, FreeIPA...)
      urls: [ldaps://dc1.contoso.com, ldaps://dc2.contoso.com]
      ca_cert: /etc/sdl/contoso-ca.pem
      bind_dn: sdl-search@contoso.com      # a read-only search account
      bind_password_env: SDL_LDAP_PASSWORD
      user_base_dn: OU=Staff,DC=contoso,DC=com
      group_base_dn: OU=Groups,DC=contoso,DC=com   # follows nested groups on AD
      group_mapping: [...]
      require_totp: false                  # true: also ask for an SDL TOTP code
```

Users pick the directory on the sign-in form and type their usual name and
password; `sdl login --provider ad`. SDL finds the user with the search
account, then binds as the user to check the password. Passwords only travel
over TLS (`ldaps://` or `start_tls: true`); SDL refuses a plain `ldap://`
configuration unless `allow_insecure: true` (test labs only). An empty
password is always refused, so an anonymous bind cannot pass for a sign-in.
Needs `pip install 'sooperdooperlooper[ldap]'`.

### Microsoft Entra ID, Okta, Keycloak, Google... (`idp.oidc`)

```yaml
api:
  public_url: https://sdl.example.com     # what browsers see, behind a reverse proxy
modules:
  entra:
    type: idp.oidc
    config:
      display_name: Entra ID
      issuer: https://login.microsoftonline.com/<tenant id>/v2.0
      client_id: <application (client) id>
      client_secret_env: SDL_OIDC_SECRET
      groups_claim: groups                # Entra: add the groups claim in Token configuration
      group_mapping:
        - group: 0f8fad5b-d9cb-469f-a165-70867728950e   # Entra group object id
          roles: [operator]
          groups: [web]
```

Register SDL as a web application with redirect URI
`https://sdl.example.com/api/v1/auth/sso/entra/callback`. The page then shows
a **Sign in with Entra ID** button; on the command line, `sdl login --sso entra`
prints an address to open, and the page shows a one-time code to paste back.

SDL uses the authorization code flow with PKCE, `state` and `nonce`, and checks
the ID token's signature against the provider's published keys, its issuer,
audience, expiry and nonce. Users with very many groups get no `groups` claim
from Entra ID ("groups overage"): map **app roles** instead
(`groups_claim: roles`). Multi-factor sign-in is the provider's business
(conditional access). Needs `pip install 'sooperdooperlooper[oidc]'`.

### SAML 2.0 (`idp.saml`)

```yaml
  adfs:
    type: idp.saml
    config:
      display_name: Contoso AD FS
      sp_entity_id: https://sdl.example.com/saml
      idp_entity_id: http://adfs.contoso.com/adfs/services/trust
      idp_sso_url: https://adfs.contoso.com/adfs/ls/
      idp_certificates: [/etc/sdl/adfs-signing.pem]   # list two while it rolls over
      groups_attribute: http://schemas.microsoft.com/ws/2008/06/identity/claims/groups
      group_mapping: [...]
```

Give the identity provider SDL's metadata from
`https://sdl.example.com/api/v1/auth/sso/adfs/metadata`. SDL checks the XML
signature with the configured certificate and reads only the signed part of
the response (so a wrapped, unsigned assertion is ignored), then the issuer,
audience, recipient, validity window, and that the response answers the
request SDL sent. Assertions must not be encrypted. Needs
`pip install 'sooperdooperlooper[saml]'`.

## Sessions

Signing in returns a session token, used as a bearer token exactly like an API
token. It ends after `session_ttl` (8 hours) or `session_idle` (1 hour without
a request), on sign-out, and when SDL restarts (sessions live in memory).
The web page keeps it in the browser tab only.

## API tokens for machine clients

`auth.static_token` clients are unchanged and can now be limited too:

```yaml
        - id: ci-web
          token_sha256: ...
          roles: [operator]
          access: {groups: [web]}     # without access: every system
```

## Audit

Every sign-in (success, failure, lockout, refused directory user), sign-out,
password change and reset, authenticator set-up and reset, and every user
added, changed (with what changed, before and after), imported, provisioned
or removed is in the audit log (`sdl logs --action auth`, `--action user`).
No password, hash or TOTP secret ever is.

## API

| Method and path                               | Permission     |                                    |
|-----------------------------------------------|----------------|------------------------------------|
| `GET /api/v1/auth/providers`                  | none           | how to sign in                     |
| `POST /api/v1/auth/login`                     | none           | password (+ `code`) sign-in        |
| `GET /api/v1/auth/sso/{id}/start`, `.../callback`, `.../metadata`, `POST /api/v1/auth/sso/exchange` | none | single sign-on |
| `POST /api/v1/auth/logout`                    | signed in      |                                    |
| `GET /api/v1/me`, `POST /api/v1/me/password`, `POST /api/v1/me/mfa/totp[/confirm]` | signed in | your own account |
| `GET /api/v1/roles`                           | signed in      |                                    |
| `GET /api/v1/users[/{name}]`                  | `users:read`   |                                    |
| `POST /api/v1/users`, `PATCH`/`DELETE /api/v1/users/{name}`, `POST .../password`, `DELETE .../mfa`, `POST .../unlock` | `users:write` + every system | |
| `GET /api/v1/idps`                            | `users:read`   |                                    |
| `GET`/`POST /api/v1/idps/{id}/users`          | `users:write`  | directory search and import        |
