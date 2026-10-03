from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sdl.api.app import create_app
from sdl.cli import main as cli
from tests.conftest import ADMIN_TOKEN


@pytest.fixture
def api(
    orchestrator_factory: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    store = {"inventory": {"type": "inventory.store", "config": {"path": str(tmp_path / "i.json")}}}
    with TestClient(create_app(orchestrator_factory(extra_modules=store))) as client:
        client.headers["Authorization"] = f"Bearer {ADMIN_TOKEN}"
        monkeypatch.setattr(cli, "client", lambda args: contextlib.nullcontext(client))
        yield client


def answers(monkeypatch: pytest.MonkeyPatch, *replies: str) -> None:
    queue = list(replies)
    monkeypatch.setattr("builtins.input", lambda prompt="": queue.pop(0))


def test_parse_selection() -> None:
    assert cli.parse_selection("1,3-4", 5) == [0, 2, 3]
    assert cli.parse_selection(" 2 5 2 ", 5) == [1, 4]
    assert cli.parse_selection("all", 3) == [0, 1, 2]
    for bad in ("0", "6", "3-1", "x", ""):
        with pytest.raises(cli.CliError):
            cli.parse_selection(bad, 5)


def test_add_list_and_remove_systems(api: TestClient, capsys: pytest.CaptureFixture[str]) -> None:
    add = [
        "systems", "add", "web1", "--inventory", "inventory", "--fqdn", "web1.example.com",
        "--ip", "10.0.0.11", "--ip", "2001:db8::11", "--hostname", "web1", "-g", "web",
        "--service-account", "sdl-svc", "--service-account-path", "svc/web1",
    ]  # fmt: skip
    assert cli.main(add) == 0
    assert "connects to web1.example.com" in capsys.readouterr().out
    assert cli.main(add) == 2  # already there
    assert "already exists" in capsys.readouterr().err
    assert cli.main([*add, "--replace"]) == 0
    capsys.readouterr()

    assert cli.main(["systems", "list", "--source", "inventory", "--json"]) == 0
    [web1] = json.loads(capsys.readouterr().out)
    assert web1["secret_path"] == "linux/web1/root"
    assert web1["addresses"] == ["10.0.0.11", "2001:db8::11"]
    assert web1["service_account"]["credential_path"] == "svc/web1"

    assert cli.main(["systems", "list"]) == 0
    table = capsys.readouterr().out
    assert "web1.example.com" in table and "sdl-svc" in table and "vm1" in table

    assert cli.main(["systems", "remove", "web1", "--inventory", "inventory"]) == 0
    assert cli.main(["systems", "show", "web1"]) == 2


def test_import_systems_from_a_file(
    api: TestClient, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "systems.yaml"
    path.write_text(
        "systems:\n"
        "  - {name: db1, fqdn: db1.example.com, secret_path: linux/db1/root}\n"
        "  - {name: db2, addresses: [10.0.0.22], secret_path: linux/db2/root}\n"
        "  - {name: vm1, addresses: [10.0.0.1], secret_path: x}\n"
    )
    assert cli.main(["systems", "import", str(path), "--inventory", "inventory"]) == 1
    captured = capsys.readouterr()
    assert "db1: stored" in captured.out and "db2: stored" in captured.out
    assert "vm1: 409" in captured.err


def test_interactive_rollover_selects_from_the_list(
    api: TestClient, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers(monkeypatch, "1,3", "y")
    code = cli.main(["rollover", "run", "-i", "-r", "picked", "--json"])
    out = capsys.readouterr().out
    run = json.loads(out[out.index("{") :])
    assert code == 0
    assert [r["target"] for r in run["results"]] == ["vm1", "vm3"]
    assert all(r["status"] == "succeeded" for r in run["results"])


def test_interactive_rollover_can_be_cancelled(
    api: TestClient, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers(monkeypatch, "2", "n")
    assert cli.main(["rollover", "run", "-i", "--search", "vm", "-r", "x"]) == 1
    assert "Cancelled" in capsys.readouterr().out
    assert api.get("/api/v1/rollovers").json() == []


def test_parse_time() -> None:
    day = cli.parse_time("2026-10-01")
    assert (day.year, day.month, day.day, day.hour) == (2026, 10, 1, 0) and day.tzinfo
    assert cli.parse_time("2026-10-01", end=True) - day == timedelta(days=1)
    assert cli.parse_time("2026-10-01T14:30+02:00").utcoffset() == timedelta(hours=2)
    assert cli.parse_time("2026-10-01T14:30").tzinfo is not None
    assert datetime.now(UTC) - cli.parse_time("24h") > timedelta(hours=23, minutes=59)
    assert cli.parse_time("today", end=True) - cli.parse_time("today") == timedelta(days=1)
    with pytest.raises(cli.CliError, match="not a time"):
        cli.parse_time("last tuesday")


def test_review_the_log(api: TestClient, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["rollover", "run", "-t", "vm1", "-r", "rotate"]) == 0
    assert cli.main(["rollover", "run", "-t", "vm2", "-r", "check", "--dry-run"]) == 0
    capsys.readouterr()

    assert cli.main(["logs", "--system", "vm1", "-a", "rollover.target.change", "--json"]) == 0
    events = json.loads(capsys.readouterr().out)
    assert events and {(e["target"], e["action"]) for e in events} == {
        ("vm1", "rollover.target.change")
    }

    assert cli.main(["audit", "-t", "vm2", "--since", "1h", "--until", "today", "-v"]) == 0
    out = capsys.readouterr().out
    assert "rollover.target.preflight" in out and "[vm2] (linux)" in out and '"dry_run"' in out
    assert "vm1" not in out

    assert cli.main(["logs", "-u", "alice", "-o", "failure", "--newest-first"]) == 0
    assert "no events match" in capsys.readouterr().err

    assert cli.main(["logs", "--facets"]) == 0
    out = capsys.readouterr().out
    assert "Systems:" in out and "vm1" in out and "rollover.target.change" in out

    assert cli.main(["logs", "--since", "someday"]) == 2

    assert cli.main(["forwarders"]) == 0
    assert "no forwarder modules" in capsys.readouterr().err
