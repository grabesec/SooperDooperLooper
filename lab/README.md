# SDL manual QA lab

SDL, a Vault, four Linux "VMs", an LDAP directory and a stand-in log
concentrator in Docker, pre-filled with systems, secrets, users and API tokens:

```bash
./lab/lab.sh up
```

Then open http://127.0.0.1:8800/ui/ and sign in as `sdladmin` /
`lab-superuser-password`, or run
`./lab/lab.sh sdl systems list`. [docs/manual-qa.md](../docs/manual-qa.md)
describes the lab and has the step-by-step test checklist; `./lab/lab.sh help`
lists the commands.

| File                 | What it is                                                         |
|----------------------|--------------------------------------------------------------------|
| `lab.sh`             | Start, stop, reset the lab; run the CLI and the checks             |
| `docker-compose.yml` | The lab's containers                                               |
| `Dockerfile.sdl`     | SDL from this checkout, plus `labctl.py`                           |
| `labctl.py`          | Runs in the SDL container: prepares and seeds the lab (systems, superuser, users), smoke test |
| `ldap/`              | OpenLDAP with the lab's people and groups (`directory.ldif`)       |
| `vault/`             | Vault with file storage, initialized and unsealed automatically    |
| `sink/sink.py`       | Receives syslog, GELF and Splunk HEC; shows events on port 8900    |
| `import-example.yaml`| Systems for the import step of the checklist                       |

The VMs are built from `tests/integration/vm`, the same image the integration
tests use.
