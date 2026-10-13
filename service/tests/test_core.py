import asyncio

import pytest
from fastapi.testclient import TestClient

from netguard import api
from netguard.analyzer import analyze_host, analyze_network
from netguard.knowledge import match_versions
from netguard.report import build_pdf
from netguard.risk_model import extract_features, predict
from netguard.scanner import (HostScan, OpenPort, TargetNotAllowed, expand_targets,
                              parse_ports, scan_network)


def test_parse_ports():
    assert parse_ports("22,80,1-3") == [1, 2, 3, 22, 80]
    assert 22 in parse_ports("top")
    for bad in ["0", "70000", "abc", "1-99999"]:
        with pytest.raises(ValueError):
            parse_ports(bad)


def test_public_targets_blocked():
    with pytest.raises(TargetNotAllowed):
        expand_targets("8.8.8.8")
    with pytest.raises(TargetNotAllowed):
        expand_targets("10.0.0.0/16")
    assert expand_targets("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]
    assert expand_targets("127.0.0.1") == ["127.0.0.1"]


def test_version_rules():
    assert match_versions("220 (vsFTPd 2.3.4)")[0]["cve"] == "CVE-2011-2523"
    assert match_versions("Server: Apache/2.4.49 (Unix)")[0]["severity"] == "critical"
    assert match_versions("SSH-2.0-OpenSSH_9.6") == []


def _host(*ports, banners=None):
    banners = banners or {}
    return HostScan("10.0.0.5", [OpenPort(p, banners.get(p), 1.0) for p in ports])


def test_risk_is_monotonic():
    web = analyze_host(_host(443))["risk"]["score"]
    mixed = analyze_host(_host(22, 80, 443))["risk"]["score"]
    bad = analyze_host(_host(23, 445, 3389, 6379))["risk"]["score"]
    assert web < mixed < bad
    assert analyze_host(_host(2375))["risk"]["level"] in ("high", "critical")
    assert analyze_host(_host(443))["risk"]["level"] == "low"


def test_vulnerable_banner_raises_risk():
    clean = analyze_host(_host(21, banners={21: "220 ProFTPD Server"}))["risk"]["score"]
    vuln = analyze_host(_host(21, banners={21: "220 (vsFTPd 2.3.4)"}))
    assert vuln["risk"]["score"] > clean
    assert vuln["risk"]["level"] == "critical"
    assert any(f["cve"] == "CVE-2011-2523" for f in vuln["findings"])


def test_features_empty():
    assert extract_features([])["n_open"] == 0
    assert predict(extract_features([]))["level"] == "low"


def test_pdf_report_handles_hostile_banner():
    banner = "SSH-2.0-OpenSSH_7.2 <b>&</b> \u202e\u4e2d\u6587"
    report = analyze_network("10.0.0.5", 1, [_host(22, 2375, banners={22: banner})], 0.4)
    pdf = build_pdf(report)
    assert pdf.startswith(b"%PDF") and len(pdf) > 2000


def test_empty_report_pdf():
    assert build_pdf(analyze_network("10.0.0.9", 1, [], 0.1)).startswith(b"%PDF")


def test_scanner_finds_open_port_and_banner():
    async def run():
        async def handler(r, w):
            w.write(b"SSH-2.0-OpenSSH_7.2\r\n")
            await w.drain()
            w.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            res = await scan_network(["127.0.0.1"], [port, 1], timeout=0.5)
        return port, res

    port, res = asyncio.run(run())
    assert len(res) == 1 and res[0].open_ports[0].port == port
    assert "OpenSSH_7.2" in res[0].open_ports[0].banner


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(api, "TOKEN", "secret")
    return TestClient(api.app)


def test_api_requires_token(client):
    assert client.get("/api/health").status_code == 401
    assert client.get("/api/health", headers={"X-Token": "nope"}).status_code == 401
    assert client.get("/api/health", headers={"X-Token": "secret"}).status_code == 200


def test_api_scan_and_pdf(client):
    h = {"X-Token": "secret"}
    assert client.post("/api/scan", json={"target": "8.8.8.8"}, headers=h).status_code == 400
    assert client.post("/api/scan", json={"target": "127.0.0.1", "ports": "99999"}, headers=h).status_code == 422
    r = client.post("/api/scan", json={"target": "127.0.0.1", "ports": "1"}, headers=h)
    assert r.status_code == 200
    pdf = client.get(f"/api/report/{r.json()['id']}/pdf", headers=h)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert client.get("/api/report/unknown/pdf", headers=h).status_code == 404
