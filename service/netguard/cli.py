import argparse
import asyncio
import sys
import time
from pathlib import Path

from .analyzer import analyze_network
from .report import build_pdf
from .scanner import expand_targets, parse_ports, scan_network

COLORS = {"low": "32", "medium": "33", "high": "38;5;208", "critical": "31", "info": "36"}


def paint(text, level):
    return f"\033[{COLORS.get(level, '0')}m{text}\033[0m" if sys.stdout.isatty() else text


def main(argv=None):
    ap = argparse.ArgumentParser(prog="netguard")
    ap.add_argument("target")
    ap.add_argument("-p", "--ports", default="top")
    ap.add_argument("--timeout", type=float, default=0.8)
    ap.add_argument("--pdf")
    ap.add_argument("--allow-public", action="store_true")
    args = ap.parse_args(argv)
    try:
        ips = expand_targets(args.target, allow_public=args.allow_public)
        ports = parse_ports(args.ports)
        start = time.perf_counter()
        results = asyncio.run(scan_network(ips, ports, timeout=args.timeout))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    report = analyze_network(args.target, len(ips), results, time.perf_counter() - start)
    risk = report["risk"]
    print(f"\n{report['target']}  risk {paint(risk['level'].upper(), risk['level'])} ({risk['score']}/100)")
    print(report["narrative"], "\n")
    for h in report["hosts"]:
        print(f"{h['ip']}  {paint(h['risk']['level'].upper(), h['risk']['level'])} ({h['risk']['score']}/100)")
        for p in h["ports"]:
            print(f"   {p['port']:>5}/tcp  {p['service']}")
        for f in h["findings"]:
            cve = f" [{f['cve']}]" if f["cve"] else ""
            print(f"   - {paint(f['severity'].upper(), f['severity'])}: {f['title']}{cve}")
            print(f"       fix: {f['remediation'][0]}")
        print()
    if args.pdf:
        Path(args.pdf).write_bytes(build_pdf(report))
        print(f"PDF written to {args.pdf}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
