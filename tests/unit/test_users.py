from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sdl.api.app import create_app
from sdl.core import superuser, totp
from sdl.core.orchestrator import ConfigError
from sdl.core.passwords import hash_password
from tests.conftest import ADMIN_TOKEN, AUDITOR_TOKEN

SU_PASSWORD = "correct horse battery staple"
GOOD_PASSWORD = "Sup3r-Secret-Passw0rd"


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def write_superuser(path: Path, name: str = "root-admin", totp_secret: str | None = None) -> None:
    superuser.save(
        path,
        superuser.Superuser(
            name=name,
            password_hash=hash_password(SU_PASSWORD),
            totp_secret=totp_secret,  # type: ignore[arg-type]
        ),
    )


@pytest.fixture
def su_file(tmp_path: Path) -> Path:
    path = tmp_path / "superuser.json"
    write_superuser(path)
    return path


@pytest.fixture
def make_api(orchestrator_factory: Any, tmp_path: Path, su_file: Path) -> Iterator[Any]:
    clients: list[TestClient] = []

    def make(**identity: Any) -> TestClient:
        modules = {
            "users": {"type": "users.store", "config": {"path": str(tmp_path / "users.json")}},
            "inventory": {
                "type": "inventory.store",
                "config": {"path": str(tmp_path / "inventory.json")},
            },
        }
        orchestrator = orchestrator_factory(
            extra_modules=modules,
            identity={"superuser_file": str(su_file), "max_failed_logins": 3, **identity},
        )
        client = TestClient(create_app(orchestrator))
        client.__enter__()
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture
def api(make_api: Any) -> TestClient:
    client: TestClient = make_api()
    return client


def login(api: TestClient, username: str, password: str, **extra: Any) -> Any:
    return api.post(
        "/api/v1/auth/login", json={"username": username, "password": password, **extra}
    )


def su_token(api: TestClient) -> str:
    response = login(api, "root-admin", SU_PASSWORD)
    assert response.status_code == 200, response.text
    token: str = response.json()["token"]
    return token


def add_user(api: TestClient, token: str, name: str, **body: Any) -> Any:
    payload = {"name": name, "password": GOOD_PASSWORD, "roles": ["operator"], **body}
    response = api.post("/api/v1/users", json=payload, headers=bearer(token))
    assert response.status_code == 201, response.text
    return response.json()


def user_token(api: TestClient, name: str, password: str = GOOD_PASSWORD) -> str:
    """Sign in as a new user and get past the forced password change."""
    first = login(api, name, password).json()
    token: str = first["token"]
    if "password_change" in first["pending"]:
        new = password + "-changed"
        response = api.post(
            "/api/v1/me/password",
            json={"current_password": password, "new_password": new},
            headers=bearer(token),
        )
        assert response.status_code == 204, response.text
    return token


def audit(api: TestClient, **params: Any) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = api.get(
        "/api/v1/audit", params=params, headers=bearer(ADMIN_TOKEN)
    ).json()
    return events


# -- the superuser file ---------------------------------------------------------------------


def test_superuser_file_keeps_only_a_hash_and_is_private(su_file: Path) -> None:
    assert os.stat(su_file).st_mode & 0o777 == 0o600
    text = su_file.read_text()
    assert SU_PASSWORD not in text and "$argon2id$" in text
    os.chmod(su_file, 0o644)
    with pytest.raises(superuser.SuperuserFileError, match="chmod 600"):
        superuser.load(su_file)


def test_sdl_refuses_to_start_with_a_readable_or_missing_superuser_file(
    orchestrator_factory: Any, su_file: Path, tmp_path: Path
) -> None:
    os.chmod(su_file, 0o640)
    with pytest.raises(ConfigError, match="accessible to other users"):
        orchestrator_factory(identity={"superuser_file": str(su_file)}).load()
    with pytest.raises(ConfigError, match="sdl superuser set"):
        orchestrator_factory(identity={"superuser_file": str(tmp_path / "nope.json")}).load()


def test_superuser_signs_in_and_manages_users(api: TestClient) -> None:
    assert login(api, "root-admin", "wrong password!").status_code == 401
    token = su_token(api)
    me = api.get("/api/v1/me", headers=bearer(token)).json()
    assert me["actor"]["roles"] == ["superuser"] and me["access"] is None
    assert "users:write" in me["permissions"] and me["signed_in_with"] == "superuser"
    add_user(api, token, "Alice", display_name="Alice A.", access={"groups": ["web"]})
    users = api.get("/api/v1/users", headers=bearer(token)).json()
    assert [u["name"] for u in users] == ["alice"]
    assert "password_hash" not in users[0] and users[0]["has_password"] is True
    # Nobody can take the superuser's name or role.
    clash = api.post(
        "/api/v1/users", json={"name": "root-admin", "roles": []}, headers=bearer(token)
    )
    assert clash.status_code == 409
    bad_role = api.post(
        "/api/v1/users", json={"name": "eve", "roles": ["superuser"]}, headers=bearer(token)
    )
    assert bad_role.status_code == 400 and "unassignable" in bad_role.json()["detail"]


def test_changing_the_superuser_file_ends_its_sessions(api: TestClient, su_file: Path) -> None:
    token = su_token(api)
    assert api.get("/api/v1/me", headers=bearer(token)).status_code == 200
    write_superuser(su_file)
    os.utime(su_file, (1, 1))  # a different mtime, even on coarse file systems
    assert api.get("/api/v1/me", headers=bearer(token)).status_code == 401
    assert login(api, "root-admin", SU_PASSWORD).status_code == 200


def test_superuser_totp(api: TestClient, su_file: Path) -> None:
    secret = totp.new_secret()
    write_superuser(su_file, totp_secret=secret)
    first = login(api, "root-admin", SU_PASSWORD)
    assert first.status_code == 401 and first.json()["detail"]["mfa_required"] is True
    code = totp.code_at(secret, totp.current_step())
    assert login(api, "root-admin", SU_PASSWORD, code=code).status_code == 200
    # The same code cannot be used twice.
    assert login(api, "root-admin", SU_PASSWORD, code=code).status_code == 401


def test_cli_creates_the_superuser_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from sdl.cli import main as cli

    path = tmp_path / "etc" / "su.json"
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("short\n"))
    args = ["superuser", "set", "-f", str(path), "--name", "Boss", "--password-stdin"]
    assert cli.main(args) == 2
    assert "at least 12" in capsys.readouterr().err
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(f"{SU_PASSWORD}\n"))
    assert cli.main(args) == 0
    saved = superuser.load(path)
    assert saved.name == "boss" and os.stat(path).st_mode & 0o777 == 0o600
    assert cli.main(["superuser", "show", "-f", str(path)]) == 0
    assert "boss" in capsys.readouterr().out


# -- local users ------------------------------------------------------------------------------


def test_new_user_must_change_password_before_anything_else(api: TestClient) -> None:
    su = su_token(api)
    add_user(api, su, "alice")
    first = login(api, "alice", GOOD_PASSWORD).json()
    assert first["pending"] == ["password_change"]
    token = first["token"]
    assert api.get("/api/v1/systems", headers=bearer(token)).status_code == 403
    me = api.get("/api/v1/me", headers=bearer(token)).json()
    assert me["pending"] == ["password_change"] and me["can_change_password"] is True
    weak = api.post(
        "/api/v1/me/password",
        json={"current_password": GOOD_PASSWORD, "new_password": "alice-password-1"},
        headers=bearer(token),
    )
    assert weak.status_code == 400 and "user name" in weak.json()["detail"]
    wrong = api.post(
        "/api/v1/me/password",
        json={"current_password": "not it at all", "new_password": "An0ther-Good-One!"},
        headers=bearer(token),
    )
    assert wrong.status_code == 403
    ok = api.post(
        "/api/v1/me/password",
        json={"current_password": GOOD_PASSWORD, "new_password": "An0ther-Good-One!"},
        headers=bearer(token),
    )
    assert ok.status_code == 204
    assert api.get("/api/v1/systems", headers=bearer(token)).status_code == 200
    assert login(api, "alice", GOOD_PASSWORD).status_code == 401
    assert login(api, "ALICE", "An0ther-Good-One!").json()["pending"] == []


def test_required_mfa_enrollment_and_codes(make_api: Any) -> None:
    api = make_api(require_mfa=True)
    su = su_token(api)
    add_user(api, su, "bob")
    token = user_token(api, "bob")
    me = api.get("/api/v1/me", headers=bearer(token)).json()
    assert me["pending"] == ["mfa_enrollment"]
    assert api.get("/api/v1/systems", headers=bearer(token)).status_code == 403
    enrollment = api.post("/api/v1/me/mfa/totp", headers=bearer(token)).json()
    assert enrollment["uri"].startswith("otpauth://totp/SDL%3Abob?")
    bad = api.post("/api/v1/me/mfa/totp/confirm", json={"code": "000000"}, headers=bearer(token))
    assert bad.status_code == 400
    code = totp.code_at(enrollment["secret"], totp.current_step())
    good = api.post("/api/v1/me/mfa/totp/confirm", json={"code": code}, headers=bearer(token))
    assert good.status_code == 204
    assert api.get("/api/v1/systems", headers=bearer(token)).status_code == 200

    password = GOOD_PASSWORD + "-changed"
    assert login(api, "bob", password).json()["detail"]["mfa_required"] is True
    # The code used to confirm the authenticator cannot be replayed to sign in.
    assert login(api, "bob", password, code=code).status_code == 401
    next_code = totp.code_at(enrollment["secret"], totp.current_step() + 1)
    assert login(api, "bob", password, code=next_code).status_code == 200

    # A lost phone: the administrator resets the authenticator.
    assert api.delete("/api/v1/users/bob/mfa", headers=bearer(su)).status_code == 204
    assert api.get("/api/v1/users/bob", headers=bearer(su)).json()["mfa"] is False
    assert login(api, "bob", password).json()["pending"] == ["mfa_enrollment"]


def test_lockout_after_failed_sign_ins(api: TestClient) -> None:
    su = su_token(api)
    add_user(api, su, "carol", password=GOOD_PASSWORD)
    for _ in range(3):
        assert login(api, "carol", "wrong-password-x").status_code == 401
    locked = login(api, "carol", GOOD_PASSWORD)
    assert locked.status_code == 401 and "too many" in locked.json()["detail"]
    assert api.post("/api/v1/users/carol/unlock", headers=bearer(su)).status_code == 204
    assert login(api, "carol", GOOD_PASSWORD).status_code == 200
    events = audit(api, action="auth.login", actor="carol")
    assert [e["outcome"] for e in events] == ["failure"] * 3 + ["denied", "success"]


def test_unknown_users_and_wrong_passwords_look_the_same(api: TestClient) -> None:
    su = su_token(api)
    add_user(api, su, "dave")
    unknown = login(api, "nobody", GOOD_PASSWORD)
    wrong = login(api, "dave", "not the password")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_disabling_or_removing_a_user_ends_their_session(api: TestClient) -> None:
    su = su_token(api)
    add_user(api, su, "erin")
    token = user_token(api, "erin")
    assert api.get("/api/v1/systems", headers=bearer(token)).status_code == 200
    changed = api.patch("/api/v1/users/erin", json={"enabled": False}, headers=bearer(su))
    assert changed.status_code == 200 and changed.json()["enabled"] is False
    assert api.get("/api/v1/systems", headers=bearer(token)).status_code == 401
    assert login(api, "erin", GOOD_PASSWORD + "-changed").json()["detail"] == (
        "this account is disabled"
    )
    api.patch("/api/v1/users/erin", json={"enabled": True}, headers=bearer(su))
    token = login(api, "erin", GOOD_PASSWORD + "-changed").json()["token"]
    assert api.delete("/api/v1/users/erin", headers=bearer(su)).status_code == 204
    assert api.get("/api/v1/me", headers=bearer(token)).status_code == 401


def test_admin_password_reset_and_logout(api: TestClient) -> None:
    su = su_token(api)
    add_user(api, su, "frank")
    token = user_token(api, "frank")
    reset = api.post(
        "/api/v1/users/frank/password", json={"password": "Brand-New-Pass-42"}, headers=bearer(su)
    )
    assert reset.status_code == 204
    assert api.get("/api/v1/me", headers=bearer(token)).status_code == 401
    again = login(api, "frank", "Brand-New-Pass-42").json()
    assert again["pending"] == ["password_change"]
    assert api.post("/api/v1/auth/logout", headers=bearer(again["token"])).status_code == 204
    assert api.get("/api/v1/me", headers=bearer(again["token"])).status_code == 401


def test_sessions_expire_when_idle(make_api: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    api = make_api(session_idle=60)
    token = su_token(api)
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now + 120)
    assert api.get("/api/v1/me", headers=bearer(token)).status_code == 401


# -- assignments: groups and individual systems --------------------------------------------


def test_assigned_groups_and_systems_limit_what_a_user_sees_and_rolls_over(
    api: TestClient,
) -> None:
    su = su_token(api)
    add_user(api, su, "web-op", access={"groups": ["web"], "systems": []})
    token = user_token(api, "web-op")
    me = api.get("/api/v1/me", headers=bearer(token)).json()
    assert me["access"] == {"all_systems": False, "groups": ["web"], "systems": []}

    listed = api.get("/api/v1/systems", headers=bearer(token)).json()
    assert [s["name"] for s in listed["systems"]] == ["vm1", "vm2"]
    assert api.get("/api/v1/systems/vm3", headers=bearer(token)).status_code == 404
    assert len(api.get("/api/v1/targets", headers=bearer(token)).json()) == 2

    denied = api.post(
        "/api/v1/rollovers", json={"targets": ["vm3"], "reason": "r"}, headers=bearer(token)
    )
    assert denied.status_code == 400 and "unknown target" in denied.json()["detail"]
    run = api.post(
        "/api/v1/rollovers?wait=true", json={"all": True, "reason": "mine"}, headers=bearer(token)
    ).json()
    assert sorted(r["target"] for r in run["results"]) == ["vm1", "vm2"]

    # An individual system added later widens the reach without a new sign-in.
    api.patch(
        "/api/v1/users/web-op",
        json={"access": {"groups": ["web"], "systems": ["vm3"]}},
        headers=bearer(su),
    )
    assert api.get("/api/v1/systems/vm3", headers=bearer(token)).status_code == 200


def test_runs_and_logs_show_only_assigned_systems(api: TestClient) -> None:
    su = su_token(api)
    everything = api.post(
        "/api/v1/rollovers?wait=true", json={"all": True, "reason": "all"}, headers=bearer(su)
    ).json()
    add_user(api, su, "db-auditor", roles=["auditor"], access={"systems": ["vm3"]})
    token = user_token(api, "db-auditor")

    runs = api.get("/api/v1/rollovers", headers=bearer(token)).json()
    assert [r["target"] for r in runs[0]["results"]] == ["vm3"]
    one = api.get(f"/api/v1/rollovers/{everything['id']}", headers=bearer(token)).json()
    assert [r["target"] for r in one["results"]] == ["vm3"]

    events = api.get("/api/v1/audit?limit=1000", headers=bearer(token)).json()
    targets = {e["target"] for e in events if e["target"]}
    assert targets == {"vm3"}
    assert all(e["target"] == "vm3" or "db-auditor" in (e["actor"]["id"],) for e in events)
    facets = api.get("/api/v1/audit/facets", headers=bearer(token)).json()
    assert set(facets["targets"]) == {"vm3"}
    # Unrestricted auditors still see every system.
    assert set(
        api.get("/api/v1/audit/facets", headers=bearer(AUDITOR_TOKEN)).json()["targets"]
    ) >= {"vm1", "vm2", "vm3"}


def test_restricted_users_cannot_widen_their_reach(api: TestClient) -> None:
    su = su_token(api)
    add_user(api, su, "web-admin", roles=["admin"], access={"groups": ["web"]})
    token = user_token(api, "web-admin")
    assert api.get("/api/v1/users", headers=bearer(token)).status_code == 200
    create = api.post("/api/v1/users", json={"name": "x", "roles": []}, headers=bearer(token))
    assert create.status_code == 403 and "every system" in create.json()["detail"]
    self_widen = api.patch(
        "/api/v1/users/web-admin", json={"access": {"all_systems": True}}, headers=bearer(token)
    )
    assert self_widen.status_code == 403

    url = "/api/v1/inventory/inventory/systems"
    db = {"name": "db9", "host": "db9.test", "secret_path": "x", "groups": ["db"]}
    assert api.put(f"{url}/db9", json=db, headers=bearer(token)).status_code == 403
    web = {**db, "name": "web9", "groups": ["web"]}
    assert api.put(f"{url}/web9", json=web, headers=bearer(token)).status_code == 200
    assert api.put(f"{url}/db9", json=db, headers=bearer(su)).status_code == 200
    assert api.delete(f"{url}/db9", headers=bearer(token)).status_code == 404


def test_static_api_tokens_can_be_limited_too(orchestrator_factory: Any) -> None:
    from sdl.modules.auth_static_token import hash_token

    orchestrator = orchestrator_factory()
    clients = orchestrator.settings.modules["auth"].config["clients"]
    clients.append(
        {
            "id": "ci-web",
            "token_sha256": hash_token("ci-token"),
            "roles": ["operator"],
            "access": {"groups": ["web"]},
        }
    )
    with TestClient(create_app(orchestrator)) as api:
        listed = api.get("/api/v1/systems", headers=bearer("ci-token")).json()
        assert [s["name"] for s in listed["systems"]] == ["vm1", "vm2"]


# -- audit -----------------------------------------------------------------------------------


def test_user_changes_are_audited_without_secrets(api: TestClient, tmp_path: Path) -> None:
    su = su_token(api)
    add_user(api, su, "gina", access={"groups": ["web"]})
    api.patch(
        "/api/v1/users/gina",
        json={"roles": ["auditor"], "access": {"systems": ["vm3"]}},
        headers=bearer(su),
    )
    api.delete("/api/v1/users/gina", headers=bearer(su))
    events = audit(api, action="user")
    assert [e["action"] for e in events] == ["user.create", "user.update", "user.delete"]
    assert all(e["actor"]["id"] == "root-admin" and e["module"] == "users" for e in events)
    changes = events[1]["details"]["changes"]
    assert changes["roles"] == {"from": ["operator"], "to": ["auditor"]}
    assert changes["access"]["to"]["systems"] == ["vm3"]
    log = (tmp_path / "audit.jsonl").read_text()
    assert GOOD_PASSWORD not in log and "$argon2" not in log and SU_PASSWORD not in log


def test_user_file_is_private_and_holds_no_plain_passwords(api: TestClient, tmp_path: Path) -> None:
    su = su_token(api)
    add_user(api, su, "hank")
    path = tmp_path / "users.json"
    assert os.stat(path).st_mode & 0o777 == 0o600
    stored = json.loads(path.read_text())["users"][0]
    assert stored["password_hash"].startswith("$argon2id$")
    assert GOOD_PASSWORD not in path.read_text()


def test_user_store_refuses_a_readable_file(make_api: Any, tmp_path: Path) -> None:
    path = tmp_path / "users.json"
    path.write_text('{"version": 1, "users": []}')
    os.chmod(path, 0o644)
    with pytest.raises(Exception, match="chmod 600"):
        make_api()


def test_providers_are_listed_for_the_sign_in_page(api: TestClient) -> None:
    providers = api.get("/api/v1/auth/providers").json()
    assert providers == [{"id": "local", "name": "SDL", "type": "local", "login": "password"}]
    roles = api.get("/api/v1/roles", headers=bearer(ADMIN_TOKEN)).json()
    assert [r["name"] for r in roles] == ["admin", "auditor", "operator"]


# -- CLI -------------------------------------------------------------------------------------


def test_cli_login_and_user_management(
    api: TestClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import contextlib

    from sdl.cli import main as cli

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.delenv("SDL_TOKEN", raising=False)
    monkeypatch.setattr(cli, "anonymous", lambda args: contextlib.nullcontext(api))
    passwords = iter([SU_PASSWORD, GOOD_PASSWORD, GOOD_PASSWORD])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(passwords))
    assert cli.main(["--url", "http://testserver", "login", "-u", "root-admin"]) == 0
    assert "Signed in as root-admin" in capsys.readouterr().out
    session = tmp_path / "config" / "sdl" / "session.json"
    assert os.stat(session).st_mode & 0o777 == 0o600
    token = json.loads(session.read_text())["token"]

    def client(args: Any) -> Any:
        api.headers["Authorization"] = f"Bearer {cli.saved_session(args.url)}"
        return contextlib.nullcontext(api)

    monkeypatch.setattr(cli, "client", client)
    url = ["--url", "http://testserver"]
    assert cli.main([*url, "users", "add", "Ivan", "-r", "operator", "-g", "web,db"]) == 0
    assert "must choose a new password" in capsys.readouterr().out
    assert cli.main([*url, "users", "set", "ivan", "--remove-group", "db", "-s", "vm3"]) == 0
    capsys.readouterr()
    assert cli.main([*url, "users", "list", "--json"]) == 0
    [ivan] = json.loads(capsys.readouterr().out)
    assert ivan["access"] == {"all_systems": False, "groups": ["web"], "systems": ["vm3"]}
    assert cli.main([*url, "users", "set", "ivan", "--disable"]) == 0
    assert "DISABLED" in capsys.readouterr().out
    assert cli.main([*url, "whoami"]) == 0
    assert "superuser" in capsys.readouterr().out
    assert cli.main([*url, "logout"]) == 0
    assert not session.exists()
    assert api.get("/api/v1/me", headers=bearer(token)).status_code == 401


def test_cli_login_asks_for_the_code(
    api: TestClient,
    su_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import contextlib

    from sdl.cli import main as cli

    secret = totp.new_secret()
    write_superuser(su_file, totp_secret=secret)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(cli, "anonymous", lambda args: contextlib.nullcontext(api))
    monkeypatch.setattr("getpass.getpass", lambda prompt="": SU_PASSWORD)
    monkeypatch.setattr(
        "builtins.input", lambda prompt="": totp.code_at(secret, totp.current_step())
    )
    assert cli.main(["login", "-u", "root-admin"]) == 0
    assert "Signed in as root-admin" in capsys.readouterr().out
