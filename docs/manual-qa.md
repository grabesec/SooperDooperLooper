# Manual QA

SDL ships a lab: SDL itself, a Vault, four Linux "VMs", an LDAP directory and
a stand-in log concentrator, all in Docker on your machine, started with one command and
already filled with systems, secrets and users. This page explains the lab and
then walks through every user story with what you should see at each step.

## The lab

You need Docker with the compose plugin (Docker Desktop, or Docker Engine with
`docker compose`) and a checkout of this repository. Nothing else: SDL, its CLI
and the helper scripts run in containers. The first start builds the images,
which needs internet access and takes a few minutes.

```bash
./lab/lab.sh up        # build, start, wait until ready, print the summary below
```

| What        | Where                                    | Notes                                         |
|-------------|------------------------------------------|-----------------------------------------------|
| Web page    | http://127.0.0.1:8800/ui/                | sign in as a user below, or with an API token |
| API docs    | http://127.0.0.1:8800/docs               |                                               |
| Vault UI    | http://127.0.0.1:8200/ui/                | token `sdl-lab-root`; secrets under `secret/sdl/` |
| Log sink    | http://127.0.0.1:8900/                   | what SDL forwarded over syslog, GELF (Graylog) and Splunk HEC |
| VMs         | `ssh -p 2221` (vm1) ... `2224` (vm4) `root@127.0.0.1` | root password: `./lab/lab.sh password web1` |

| Who        | Password                 | Signs in through        | Role (reaches)                          | Notes                                   |
|------------|--------------------------|-------------------------|-----------------------------------------|-----------------------------------------|
| `sdladmin` | `lab-superuser-password` | SDL (superuser file)    | superuser (every system)                | no authenticator until you add one       |
| `olga`     | `web-operator-pass`      | SDL (local user)        | operator (group `web`: web1, web2)      | code: `./lab/lab.sh totp olga`          |
| `ivan`     | `auditor-lab-pass`       | SDL (local user)        | auditor (every system)                  | code: `./lab/lab.sh totp ivan`          |
| `newbie`   | `temporary-password`     | SDL (local user)        | operator (system app1)                  | first sign-in: new password + authenticator |
| `alice`    | `ldap-password`          | Lab directory (LDAP)    | admin (every system), via `SDL-Admins`  |                                         |
| `bob`      | `ldap-password`          | Lab directory (LDAP)    | operator (group `web`), via `Web-Operators` |                                     |
| `carol`    | `ldap-password`          | Lab directory (LDAP)    | auditor (every system), via `SDL-Auditors` |                                      |
| `dave`     | `ldap-password`          | Lab directory (LDAP)    | none: his only group maps to nothing    | refused                                 |

Local users must use an authenticator (`require_mfa`). Instead of a phone,
`./lab/lab.sh totp olga` prints olga's current code, and `./lab/lab.sh totp <key>`
the code for a key the page shows while setting one up. A code works once, so
wait for the next one if it is refused. After 5 wrong passwords a name is
locked for 2 minutes.

API tokens, for scripts and the CLI wrapper: `admin-token`, `operator-token`
and `auditor-token`, with those roles and every system.

| System | VM  | Comes from               | Signs in with                     | Expected behaviour                   |
|--------|-----|--------------------------|-----------------------------------|--------------------------------------|
| `web1` | vm1 | SDL's inventory          | `sdl-svc`, key read from Vault    | rolls over                           |
| `web2` | vm2 | SDL's inventory          | `sdl-svc`, key read from Vault    | rolls over (Debian instead of Ubuntu)|
| `db1`  | vm3 | SDL's inventory          | `sdl-svc`, key read from Vault    | **fails on purpose**: no sudo rule   |
| `app1` | vm4 | `targets:` in `sdl.yaml` | `sdl-svc`, key file on SDL's disk | rolls over                           |

Every VM starts with the root password `lab-initial-password`, and Vault holds
it at `secret/sdl/linux/<system>/root`. Everything listens on 127.0.0.1 only.
The tokens and passwords are published in this repository: lab use only.

### Commands

```bash
./lab/lab.sh sdl systems list                      # the sdl CLI, as admin
./lab/lab.sh sdl --as operator rollover run -i -r "manual QA"
./lab/lab.sh password web1                         # root password Vault holds for web1
./lab/lab.sh root-login web1                       # does that password actually work on vm1?
./lab/lab.sh totp olga                             # olga's current authenticator code
./lab/lab.sh stop vm2 / start vm2                  # take one part down to test failures
./lab/lab.sh logs sdl                              # follow a part's logs (sdl, vault, sink, ldap, vm1...)
./lab/lab.sh smoke                                 # quick automated pass (CI runs this)
./lab/lab.sh down                                  # stop; state is kept for the next `up`
./lab/lab.sh reset                                 # throw everything away and start fresh
./lab/lab.sh destroy                               # stop and delete all state
```

State (Vault, the audit log, the inventory, users, the VMs' root passwords) survives
`down` and `up`, and any part being stopped and started. The lab rebuilds
SDL from your checkout on every `up`, so it always tests the code you have.
If ports 8800, 8200 or 8900 are taken, set `LAB_SDL_PORT`, `LAB_VAULT_PORT`
or `LAB_SINK_PORT` before `up`.

## Checklist

Start from a fresh lab (`./lab/lab.sh reset`). `sdl` below is short for
`./lab/lab.sh sdl`. Each step says what to do, then what you should see.

### 1. Root password rollover

- [ ] **1.1 Pre-flight only.** `sdl rollover run --all --dry-run -r "pre-check"`
  web1, web2 and app1 are `CHECKED`; db1 is `FAILED (unchanged)` with
  *sdl-svc may not run /usr/sbin/chpasswd with passwordless sudo*. Nothing
  changed: `./lab/lab.sh password web1` still prints `lab-initial-password`, version 1.
- [ ] **1.2 Roll over a group.** `sdl rollover run --group web -r "QA story 1"`
  The run is `SUCCEEDED`; web1 and web2 are `OK` at version 2.
- [ ] **1.3 The new password works, the old one does not.** `./lab/lab.sh root-login web1`
  *root login with Vault's password (version 2): WORKS* and *with the lab's
  initial password: fails*. By hand: `./lab/lab.sh password web1`, then
  `ssh -p 2221 root@127.0.0.1` with that password signs in.
- [ ] **1.4 Vault keeps the history.** In the Vault UI, open
  `secret/sdl/linux/web1/root`: version 2 is current (`state: active`),
  version 1 is still listed.
- [ ] **1.5 A failure leaves the system untouched.** `sdl rollover run -t db1 -r "no sudo"`
  The run is `FAILED`; db1 is `FAILED (unchanged)` with the sudo message, and `./lab/lab.sh root-login db1`
  still WORKS with the initial password.
- [ ] **1.6 Unreachable VM.** `./lab/lab.sh stop vm2`, then `sdl rollover run -t web2 -r "vm2 down"`
  `FAILED (unchanged)`, *could not connect*. `./lab/lab.sh start vm2`, then
  `./lab/lab.sh root-login web2` still WORKS with version 2.
- [ ] **1.7 Secret manager down.** `./lab/lab.sh stop vault`, then `sdl rollover run -t web1 -r "vault down"`
  `FAILED (unchanged)`, *could not read the service account credential*.
  `./lab/lab.sh start vault`; the same rollover now succeeds (version 3).
- [ ] **1.8 A system from sdl.yaml.** `sdl rollover run -t app1 -r "QA app1"`
  `OK`, version 2; `./lab/lab.sh root-login app1` WORKS.
- [ ] **1.9 Step-by-step report.** `sdl rollover list`, then `sdl rollover show <run id> -v`
  Each system lists its steps with times: start, service_account (signing in
  with the key from Vault), connect, preflight, read_previous, generate,
  escrow, change, verify, store, cleanup.

### 2. Inventory and picking systems

- [ ] **2.1 The list.** Open the web page, sign in as `sdladmin`.
  Four systems with hostname, FQDN, IP, groups and inventory (`inventory` or
  `sdl.yaml`). Typing `db` in the filter, choosing group `web`, or choosing
  inventory `sdl.yaml` narrows the list.
- [ ] **2.2 Add on the page.** *Add system*: inventory `inventory`, name `web3`,
  FQDN `web3.lab.example.com`, connect to `web3-missing`, secret path
  `linux/web3/root`, service account `sdl-svc` with credential path
  `svc/sdl-svc`, group `web`. Saved, web3 shows in the list. A dry run on it
  fails at connect (there is no such host) and changes nothing.
- [ ] **2.3 Edit and delete on the page.** *Edit* web3, add group `new`: the
  list shows it. *Delete* web3: a confirmation, then it is gone.
- [ ] **2.4 Same in the CLI.**
  `sdl systems add web3 --inventory inventory --fqdn web3.lab.example.com --host web3-missing --secret-path linux/web3/root --service-account sdl-svc --service-account-path svc/sdl-svc -g web`,
  `sdl systems show web3`, `sdl systems remove web3 --inventory inventory`.
- [ ] **2.5 Import a file.**
  `./lab/lab.sh sdl systems import /dev/stdin --inventory inventory < lab/import-example.yaml`
  mail1 and mail2 are stored and listed, in group `imported`. Remove them:
  `sdl systems remove mail1 mail2 --inventory inventory`.
- [ ] **2.6 No name can be taken twice.**
  `sdl systems add app1 --inventory inventory --host x --secret-path linux/x/root --replace`
  Refused: *a system named 'app1' already comes from inventory 'sdl.yaml'*.
- [ ] **2.7 Pick and roll over on the page.** Tick web2 and db1, reason
  "QA page", *Roll over 2 systems*, confirm. The result is *Partial*: web2
  *Succeeded* with its new version, db1 *Failed (unchanged)* with the sudo
  message; *steps* opens each system's steps. The run appears under *Recent runs*.
- [ ] **2.8 Pick in the CLI.** `sdl rollover run -i -r "QA pick"`
  A numbered list; entering `1,3` (or `1-2`) and confirming rolls over just those.

### 3. Users, sign-in and access

- [ ] **3.1 Superuser.** Sign in as `sdladmin`. The top right says *Lab
  superuser (superuser)*; every section is there, including **Users**, which
  lists olga, ivan and newbie.
- [ ] **3.2 Password plus code.** Sign out, sign in as `olga` with her
  password: the page asks for the code. `./lab/lab.sh totp olga`, type it in:
  signed in. The same code a second time is refused.
- [ ] **3.3 Access limits what a user sees.** As olga, only web1 and web2 are
  listed; no *Add system*, no Log or Users section. Rolling over web1 works.
- [ ] **3.4 Auditor.** Sign in as `ivan` (code: `./lab/lab.sh totp ivan`). All
  four systems, the Log section and the user list are there; the *Roll over*
  button stays disabled.
- [ ] **3.5 First sign-in.** Sign in as `newbie` / `temporary-password`. The
  page first asks for a new password (one containing "newbie" is refused),
  then shows an authenticator key: enter it in a phone app, or run
  `./lab/lab.sh totp <the key>`, and type the code. Then only app1 is listed.
- [ ] **3.6 Add a user on the page.** As `sdladmin`, *Users*, *Add user*:
  name `tina`, role auditor, group `db`, an initial password (not containing
  "tina"). Sign in as tina:
  the same first-sign-in steps as 3.5, then only db1 is listed. The CLI
  equivalent: `sdl users add tina --role auditor --group db` (asks for the password).
- [ ] **3.7 Change, disable, unlock.** `sdl users set olga --disable`: olga's
  next request fails and she cannot sign in (*this account is disabled*);
  `--enable` lets her back. Type a wrong password for ivan 5 times: the 6th try
  says *too many failed sign-ins*; `sdl users unlock ivan` clears it.
  `sdl users reset-mfa olga` makes her set up a new authenticator at her next
  sign-in (then `./lab/lab.sh totp olga` no longer works for her: use the key
  the page shows).
- [ ] **3.8 Directory sign-in.** Sign out, pick *Lab directory (LDAP)*, sign
  in as `alice`: admin, every system, Users section. As `bob`: operator of
  web1 and web2 only. As `carol`: auditor. As `dave`: refused with *your
  account has not been given access to SDL*. A wrong directory password gets
  the same answer as any wrong password. `./lab/lab.sh logs ldap` shows the
  binds. In the Users list alice and bob now appear, marked *Lab directory
  (LDAP)* with their directory groups.
- [ ] **3.9 Directory lookups.** `sdl idps` lists the directory;
  `sdl users search directory ""` lists alice, bob, carol and dave;
  `sdl users import directory carol --group db` adds carol's record before
  she signs in.
- [ ] **3.10 Sign-ins are audited.** `sdl logs --action auth` lists every
  sign-in, failure, lockout and dave's refusal; `sdl logs --action user` every
  user added, changed, unlocked or provisioned. No password, hash or
  authenticator key appears in `sdl logs -v --action auth --action user`.
- [ ] **3.11 Refusals in the CLI.** `sdl --as auditor rollover run -t web1 -r x`
  and `sdl --as operator logs` both end with `403: ... is not granted`;
  `sdl --as operator systems remove web1 --inventory inventory` is refused too.

### 4. Audit log review and forwarding

- [ ] **4.1 Review on the page.** As admin, in the Log section: filter by
  system `web1`, then by action type `rollover`, outcome `failure`, user
  `operator`, a date range. The *Log* button on a system's row shows that
  system's history. *Verify integrity* says the chain is intact.
- [ ] **4.2 Review in the CLI.**
  `sdl logs --system web1 --since 1h`: everything that happened to web1.
  `sdl logs --action rollover.target --outcome failure`: the db1, vm2 and Vault failures.
  `sdl logs --user operator`: what the operator did, including rollover steps run on their behalf.
  `sdl logs --action api --outcome denied`: the 403s from 3.11.
  `sdl logs --facets`: the systems, users and actions present. `-v` adds details.
- [ ] **4.3 No secrets in the log.** `sdl logs -v --since 1d | grep -c lab-initial-password` prints 0,
  and so does grepping for the current password from `./lab/lab.sh password web1`.
- [ ] **4.4 Forwarding.** Open the log sink page. Events arrive via syslog,
  Graylog and Splunk; Splunk skips `api.request` (the lab's config excludes
  it). `sdl forwarders` shows all three `ok` with nothing queued.
- [ ] **4.5 Concentrator outage.** `./lab/lab.sh stop sink`, roll over web1, then
  `sdl forwarders`: graylog and splunk are `RETRYING` with events queued
  (syslog over TCP may still say `ok` until it next writes), and
  `sdl logs --action forwarder` shows `forwarder.unavailable`. Rollovers
  work as normal meanwhile. `./lab/lab.sh start sink`: within a minute all
  three are `ok`, queues are empty, `forwarder.available` is logged, and the
  rollover's events show on the sink page.

### 5. Restarts

- [ ] **5.1 Everything survives a restart.** `./lab/lab.sh down`, then `./lab/lab.sh up`.
  Systems are still listed, `./lab/lab.sh root-login web1` WORKS, `sdl audit --verify`
  says the chain is intact, and a new rollover works. Everyone signed in on
  the page is signed out (sessions are kept in memory) and signs in again with
  the same password and authenticator. *Recent runs* starts
  empty again (runs are kept in memory; their events are still in the log:
  `sdl audit --run <id>`).

### 6. Tampering (do this last)

- [ ] **6.1 A changed log line is caught.**
  `docker compose -f lab/docker-compose.yml exec sdl sed -i '5s/admin/mallory/' /lab/state/audit.jsonl`,
  then `sdl audit --verify`: *TAMPERED: line 5 ... was modified*, and the
  page's *Verify integrity* says the same. `./lab/lab.sh reset` to start clean.

### Not in the lab yet

- **Single sign-on** (OpenID Connect such as Entra ID, and SAML): the lab has
  no test identity provider for them yet; the unit tests cover both against
  mocked providers.
- **Active Directory specifics** (nested groups, `sAMAccountName`): the lab
  directory is plain OpenLDAP.
- **NetBox** as an inventory source: the lab has no NetBox; the unit tests
  cover it against a mocked API.
- **Real Graylog and Splunk**: the sink accepts the same protocols and checks
  the HEC token, but does not index anything.
