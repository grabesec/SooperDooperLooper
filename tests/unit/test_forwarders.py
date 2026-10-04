"""Forwarding audit events to log concentrators: the core's queue and the shipped modules."""

from __future__ import annotations

import asyncio
import datetime as dt
import gzip
import json
import ssl
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from sdl.api.app import create_app
from sdl.core.audit import AuditRecorder
from sdl.core.models import Actor, ActorType, AuditEvent, AuditQuery, Outcome
from sdl.core.module import ModuleContext, ModuleError
from sdl.core.orchestrator import Orchestrator
from sdl.modules.forwarder_gelf import GelfConfig, GelfForwarderModule
from sdl.modules.forwarder_splunk_hec import SplunkHecConfig, SplunkHecForwarderModule
from sdl.modules.forwarder_syslog import SyslogConfig, SyslogForwarderModule
from tests.conftest import AUDITOR_TOKEN, FakeForwarderModule

FAST = {"retry_max_delay": 0.02}


async def eventually(check: Callable[[], bool], timeout: float = 3) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not check():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.01)


def forwarder(orchestrator: Orchestrator, instance_id: str = "siem") -> FakeForwarderModule:
    module = orchestrator.modules[instance_id]
    assert isinstance(module, FakeForwarderModule)
    return module


async def started(factory: Any, **config: Any) -> Orchestrator:
    orchestrator: Orchestrator = factory(
        extra_modules={"siem": {"type": "forwarder.fake", "config": {**FAST, **config}}}
    )
    await orchestrator.start()
    return orchestrator


async def test_every_stored_event_is_forwarded_as_stored(orchestrator_factory: Any) -> None:
    orchestrator = await started(orchestrator_factory)
    siem = forwarder(orchestrator)
    await orchestrator.audit.record("test.event", Outcome.INFO, target="vm1", password="hunter2")
    await orchestrator.stop()
    local = await orchestrator.audit.primary.query(AuditQuery())
    assert [e.action for e in siem.received] == ["system.start", "test.event", "system.stop"]
    assert [e.hash for e in siem.received] == [e.hash for e in local], "with their chain hashes"
    assert siem.received[1].details["password"] == "[redacted]"


async def test_an_unreachable_destination_never_blocks_the_local_log(
    orchestrator_factory: Any,
) -> None:
    orchestrator = await started(orchestrator_factory, fail=True)
    siem = forwarder(orchestrator)
    for n in range(5):
        await asyncio.wait_for(orchestrator.audit.record(f"test.{n}", Outcome.INFO), 1)
    assert len(await orchestrator.audit.primary.query(AuditQuery(actions=["test"]))) == 5
    await eventually(lambda: orchestrator.audit.forwarding.status()[0].failures >= 3)
    [status] = orchestrator.audit.forwarding.status()
    assert not status.ok and status.sent == 0 and status.last_error == "connection refused"

    siem.down = False
    await eventually(lambda: orchestrator.audit.forwarding.status()[0].ok)
    await eventually(lambda: any(e.action == "forwarder.available" for e in siem.received))
    actions = [e.action for e in siem.received]
    assert [a for a in actions if a.startswith(("system", "test"))] == [
        "system.start",
        *(f"test.{n}" for n in range(5)),
    ], "everything queued while it was down, in order"
    assert "forwarder.unavailable" in actions
    downs = await orchestrator.audit.primary.query(AuditQuery(actions=["forwarder"]))
    assert [(e.action, e.module) for e in downs] == [
        ("forwarder.unavailable", "siem"),
        ("forwarder.available", "siem"),
    ], "recorded once each, not on every retry"
    await orchestrator.stop()


async def test_a_full_queue_drops_the_oldest(orchestrator_factory: Any) -> None:
    orchestrator = await started(orchestrator_factory, fail=True, queue_size=3)
    siem = forwarder(orchestrator)
    for n in range(10):
        await orchestrator.audit.record(f"test.{n}", Outcome.INFO)
    siem.down = False
    await eventually(lambda: orchestrator.audit.forwarding.status()[0].ok)
    await orchestrator.stop()
    [status] = orchestrator.audit.forwarding.status()
    assert status.dropped >= 7
    assert [e.action for e in siem.received][:3] == ["test.7", "test.8", "test.9"]
    local = await orchestrator.audit.primary.query(AuditQuery(actions=["test"]))
    assert len(local) == 10, "dropped events are still in the local log"


async def test_forwarders_can_select_actions(orchestrator_factory: Any) -> None:
    orchestrator = await started(
        orchestrator_factory, actions=["rollover", "system.start"], exclude_actions=["*.target.*"]
    )
    siem = forwarder(orchestrator)
    await orchestrator.audit.record("rollover.requested", Outcome.INFO)
    await orchestrator.audit.record("rollover.target.change", Outcome.SUCCESS)
    await orchestrator.audit.record("rollover.target", Outcome.SUCCESS)
    await orchestrator.audit.record("api.request", Outcome.INFO)
    await orchestrator.stop()
    assert [e.action for e in siem.received] == [
        "system.start",
        "rollover.requested",
        "rollover.target",
    ]


async def test_shutdown_does_not_wait_for_a_dead_destination(orchestrator_factory: Any) -> None:
    orchestrator = await started(orchestrator_factory, fail=True, flush_timeout=30)
    await eventually(lambda: not orchestrator.audit.forwarding.status()[0].ok)
    await asyncio.wait_for(orchestrator.stop(), 2)


def test_forwarder_status_endpoint(orchestrator_factory: Any) -> None:
    orchestrator = orchestrator_factory(
        extra_modules={"siem": {"type": "forwarder.fake", "config": FAST}}
    )
    auditor = {"Authorization": f"Bearer {AUDITOR_TOKEN}"}
    with TestClient(create_app(orchestrator)) as api:
        response = api.get("/api/v1/forwarders", headers=auditor)
        assert response.status_code == 200
        [status] = response.json()
        assert status["id"] == "siem" and status["ok"] is True


# -- the shipped forwarder modules -------------------------------------------------------


def sample(**kwargs: Any) -> AuditEvent:
    values: dict[str, Any] = {
        "ts": dt.datetime(2026, 10, 3, 12, 0, 0, 123456, tzinfo=dt.UTC),
        "actor": Actor.system(),
        "initiated_by": Actor(type=ActorType.USER, id="bob"),
        "action": "rollover.target",
        "outcome": Outcome.FAILURE,
        "target": "web1",
        "module": "linux",
        "run_id": "run1",
        "message": 'pre-flight check failed: sudo "denied"',
        "details": {"host": "10.0.0.11"},
        "prev_hash": "0" * 64,
        "hash": "a" * 64,
    }
    values.update(kwargs)
    return AuditEvent(**values)


def context() -> ModuleContext:
    return ModuleContext("logs", AuditRecorder())


Server = tuple[int, list[bytes], Callable[[], Awaitable[None]]]


async def tcp_server(ssl_context: ssl.SSLContext | None = None) -> Server:
    received: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while data := await reader.read(65536):
            received.append(data)
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ssl_context)
    port = server.sockets[0].getsockname()[1]

    async def close() -> None:
        server.close()
        await server.wait_closed()

    return port, received, close


async def udp_server() -> Server:
    received: list[bytes] = []

    class Collect(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: Any) -> None:
            received.append(data)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(Collect, local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]

    async def close() -> None:
        transport.close()

    return port, received, close


def self_signed(tmp_path: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def split_octet_counted(stream: bytes) -> list[bytes]:
    messages = []
    while stream:
        length, _, rest = stream.partition(b" ")
        messages.append(rest[: int(length)])
        stream = rest[int(length) :]
    return messages


def test_syslog_message_format() -> None:
    module = SyslogForwarderModule(
        SyslogConfig(host="logs.example.com", hostname="sdl-1"), context()
    )
    message = module.format(sample()).decode()
    header, _, body = message.partition("] ")
    assert header.startswith("<83>1 2026-10-03T12:00:00.123456Z sdl-1 sdl ")  # authpriv.err
    assert " rollover.target [sdl@32473 event_id=" in header
    assert 'actor="orchestrator"' in header and 'initiated_by="bob"' in header
    assert 'target="web1"' in header and f'hash="{"a" * 64}"' in header
    assert json.loads(body)["message"] == 'pre-flight check failed: sudo "denied"'

    text = SyslogForwarderModule(
        SyslogConfig(host="h", body="text", facility="local3"), context()
    ).format(sample(outcome=Outcome.SUCCESS, message="ok", target=None))
    assert text.startswith(b"<157>1 ")  # local3.notice
    assert text.endswith(b"rollover.target success by system:orchestrator for bob: ok")
    with pytest.raises(ValueError, match="facility"):
        SyslogConfig(host="h", facility="nope")


async def test_syslog_over_tcp_with_octet_counting() -> None:
    port, received, close = await tcp_server()
    module = SyslogForwarderModule(SyslogConfig(host="127.0.0.1", port=port), context())
    await module.send([sample(), sample(target="web2")])
    await eventually(lambda: len(split_octet_counted(b"".join(received))) == 2)
    messages = split_octet_counted(b"".join(received))
    assert b'target="web2"' in messages[1]
    await module.stop()
    await close()


async def test_syslog_over_tls(tmp_path: Path) -> None:
    cert, key = self_signed(tmp_path)
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(cert, key)
    port, received, close = await tcp_server(server_tls)
    config = SyslogConfig(host="localhost", port=port, protocol="tls", framing="newline")
    untrusted = SyslogForwarderModule(config, context())
    with pytest.raises(ModuleError, match="certificate verify failed"):
        await untrusted.send([sample()])
    trusted = SyslogForwarderModule(config.model_copy(update={"ca_cert": cert}), context())
    await trusted.send([sample()])
    await eventually(lambda: b"".join(received).endswith(b"\n"))
    assert b"".join(received).startswith(b"<83>1 ")
    await trusted.stop()
    await close()


async def test_syslog_over_udp_and_unreachable_tcp() -> None:
    port, received, close = await udp_server()
    module = SyslogForwarderModule(
        SyslogConfig(host="127.0.0.1", port=port, protocol="udp", max_udp_size=1200), context()
    )
    await module.send([sample(), sample(details={"big": "x" * 2000})])
    await eventually(lambda: len(received) == 2)
    assert json.loads(received[0].partition(b"] ")[2])["target"] == "web1"
    assert len(received[1]) <= 1200 and b"rollover.target failure web1" in received[1]
    await module.stop()
    await close()

    port, _, close = await tcp_server()
    await close()
    dead = SyslogForwarderModule(SyslogConfig(host="127.0.0.1", port=port), context())
    with pytest.raises(ModuleError, match="cannot send"):
        await dead.send([sample()])


def gelf(**config: Any) -> GelfForwarderModule:
    return GelfForwarderModule(GelfConfig.model_validate(config), context())


async def test_gelf_over_http(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(202 if len(requests) < 3 else 500, text="input stopped")

    monkeypatch.setenv("GRAYLOG_KEY", "s3cret")
    module = gelf(
        url="http://graylog.test:12201/gelf",
        source="sdl-1",
        auth_header="X-Auth",
        auth_value_env="GRAYLOG_KEY",
        allow_insecure=True,
    )
    module._transport = httpx.MockTransport(handler)
    await module.start()
    await module.send([sample(), sample(target="web2")])
    first = json.loads(requests[0].content)
    assert requests[0].headers["X-Auth"] == "s3cret"
    assert first["version"] == "1.1" and first["host"] == "sdl-1" and first["level"] == 3
    assert first["short_message"].startswith("rollover.target failure web1 by system:")
    assert first["full_message"] == 'pre-flight check failed: sudo "denied"'
    assert first["_sdl_target"] == "web1" and first["_sdl_initiated_by"] == "bob"
    assert json.loads(first["_sdl_details"]) == {"host": "10.0.0.11"}
    assert first["timestamp"] == pytest.approx(sample().ts.timestamp())
    assert not any(key == "_id" for key in first)
    with pytest.raises(ModuleError, match="500"):
        await module.send([sample()])
    await module.stop()

    with pytest.raises(ValueError, match="url"):
        gelf(transport="http")
    with pytest.raises(ValueError, match="host"):
        gelf(transport="udp")


async def test_gelf_over_tcp_is_null_delimited() -> None:
    port, received, close = await tcp_server()
    module = gelf(transport="tcp", host="127.0.0.1", port=port)
    await module.start()
    await module.send([sample(), sample(target="web2")])
    await eventually(lambda: b"".join(received).count(b"\0") == 2)
    messages = [json.loads(m) for m in b"".join(received).split(b"\0") if m]
    assert [m["_sdl_target"] for m in messages] == ["web1", "web2"]
    await module.stop()
    await close()


async def test_gelf_over_udp_chunks_large_messages() -> None:
    port, received, close = await udp_server()
    module = gelf(transport="udp", host="127.0.0.1", port=port, chunk_size=512, compress=True)
    await module.start()
    big = sample(details={"notes": [f"line {n}" for n in range(2000)]})
    await module.send([big])
    await eventually(lambda: len(received) > 1)
    assert all(d[:2] == b"\x1e\x0f" and d[2:10] == received[0][2:10] for d in received)
    chunks = sorted(received, key=lambda d: d[10])
    assert [d[10] for d in chunks] == list(range(len(chunks))) and chunks[0][11] == len(chunks)
    message = json.loads(gzip.decompress(b"".join(d[12:] for d in chunks)))
    assert json.loads(message["_sdl_details"])["notes"][-1] == "line 1999"
    await module.stop()
    await close()


async def test_splunk_hec(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    requests: list[httpx.Request] = []
    reply = httpx.Response(200, json={"text": "Success", "code": 0})

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return reply

    config = SplunkHecConfig(url="https://splunk.test:8088/", index="security", host="sdl-1")
    with pytest.raises(ModuleError, match="SPLUNK_HEC_TOKEN"):
        await SplunkHecForwarderModule(config, context()).start()
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "hec-token")
    module = SplunkHecForwarderModule(config, context())
    module._transport = httpx.MockTransport(handler)
    await module.start()
    await module.send([sample(), sample(target="web2")])
    [request] = requests
    assert str(request.url) == "https://splunk.test:8088/services/collector/event"
    assert request.headers["Authorization"] == "Splunk hec-token"
    entries = [json.loads(line) for line in request.content.decode().splitlines()]
    assert [e["event"]["target"] for e in entries] == ["web1", "web2"]
    assert entries[0]["index"] == "security" and entries[0]["sourcetype"] == "sdl:audit"
    assert entries[0]["host"] == "sdl-1" and entries[0]["time"] == sample().ts.timestamp()
    assert entries[0]["event"]["hash"] == "a" * 64

    reply = httpx.Response(403, json={"text": "Invalid token", "code": 4})
    with pytest.raises(ModuleError, match="403: Invalid token"):
        await module.send([sample()])
    await module.stop()

    token_file = tmp_path / "hec"
    token_file.write_text("from-file\n")
    from_file = SplunkHecForwarderModule(
        config.model_copy(update={"token_file": token_file}), context()
    )
    await from_file.start()
    assert from_file._client is not None
    assert from_file._client.headers["Authorization"] == "Splunk from-file"
    await from_file.stop()
