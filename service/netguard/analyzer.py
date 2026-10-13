from __future__ import annotations

from datetime import datetime, timezone

from .knowledge import SEVERITY_ORDER, VULN_RISK_FLOOR, identify_service, match_versions
from .risk_model import extract_features, level_from_score, predict
from .scanner import HostScan


def _severity_from_risk(risk: float) -> str:
    if risk >= 9:
        return "critical"
    if risk >= 7:
        return "high"
    if risk >= 5:
        return "medium"
    if risk >= 3:
        return "low"
    return "info"


def analyze_host(host: HostScan) -> dict:
    ports_out, findings, model_ports = [], [], []
    for op in host.open_ports:
        info = identify_service(op.port, op.banner)
        vulns = match_versions(op.banner)
        worst = max((v["severity"] for v in vulns), key=SEVERITY_ORDER.get, default=None)
        risk = max(info["risk"], VULN_RISK_FLOOR.get(worst, 0))
        model_ports.append({"risk": risk, "category": info["category"], "vuln": worst})
        ports_out.append({
            "port": op.port, "service": info["service"], "category": info["category"],
            "risk": risk, "banner": op.banner, "latency_ms": op.latency_ms,
            "vulnerabilities": [v["title"] for v in vulns],
        })
        sev = _severity_from_risk(info["risk"])
        if SEVERITY_ORDER[sev] >= SEVERITY_ORDER["low"]:
            findings.append({
                "severity": sev, "port": op.port, "title": f"{info['service']} exposed on port {op.port}",
                "cve": None, "description": info["issue"], "remediation": info["remediation"],
            })
        for v in vulns:
            findings.append({"severity": v["severity"], "port": op.port, "title": v["title"],
                             "cve": v["cve"], "description": v["description"],
                             "remediation": v["remediation"]})
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["port"]))
    feats = extract_features(model_ports)
    return {
        "ip": host.ip, "open_count": len(ports_out), "ports": ports_out,
        "findings": findings, "features": feats, "risk": predict(feats),
    }


def analyze_network(target: str, scanned_hosts: int, results: list[HostScan], duration_s: float) -> dict:
    hosts = sorted((analyze_host(h) for h in results), key=lambda h: -h["risk"]["score"])
    counts = {s: 0 for s in SEVERITY_ORDER}
    for h in hosts:
        for f in h["findings"]:
            counts[f["severity"]] += 1
    if hosts:
        scores = [h["risk"]["score"] for h in hosts]
        net_score = round(0.8 * max(scores) + 0.2 * (sum(scores) / len(scores)))
    else:
        net_score = 0
    level = level_from_score(net_score) if hosts else "low"

    seen, actions = set(), []
    for h in hosts:
        for f in h["findings"]:
            if SEVERITY_ORDER[f["severity"]] < SEVERITY_ORDER["medium"]:
                continue
            step = f["remediation"][0]
            if step not in seen:
                seen.add(step)
                actions.append({"severity": f["severity"], "host": h["ip"], "port": f["port"], "action": step})
    actions.sort(key=lambda a: -SEVERITY_ORDER[a["severity"]])

    return {
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_s": round(duration_s, 1),
        "hosts_scanned": scanned_hosts,
        "hosts_with_open_ports": len(hosts),
        "risk": {"score": net_score, "level": level},
        "finding_counts": counts,
        "narrative": _narrative(hosts, scanned_hosts, level, net_score, counts),
        "top_actions": actions[:6],
        "hosts": hosts,
        "model": {"engine": hosts[0]["risk"]["engine"] if hosts else None,
                  "note": "Risk model trained on synthetic data derived from expert rules."},
    }


def _narrative(hosts: list[dict], scanned: int, level: str, score: int, counts: dict) -> str:
    if not hosts:
        return (f"{scanned} address(es) scanned: no open ports found on the selected port list. "
                "This does not prove the hosts are safe; widen the port range to be sure.")
    serious = counts["critical"] + counts["high"]
    text = (f"{len(hosts)} of {scanned} scanned address(es) expose services. "
            f"Overall risk is {level.upper()} ({score}/100) with {counts['critical']} critical, "
            f"{counts['high']} high and {counts['medium']} medium findings.")
    worst = hosts[0]
    if serious:
        text += (f" The most exposed host is {worst['ip']} ({worst['risk']['level']}, "
                 f"{worst['risk']['score']}/100); fix the critical and high findings first.")
    else:
        text += " No critical or high-severity issues were detected; focus on hardening the remaining items."
    return text
