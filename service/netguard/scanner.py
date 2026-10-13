from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass, field

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993,
    995, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 5984, 6379, 8000,
    8080, 8443, 9200, 11211, 27017,
]
HTTP_PORTS = {80, 8000, 8080}
MAX_PORTS = 5000
MAX_PROBES = 100_000
BANNER_TIMEOUT = 1.0


class TargetNotAllowed(ValueError):
    pass


@dataclass
class OpenPort:
    port: int
    banner: str | None
    latency_ms: float


@dataclass
class HostScan:
    ip: str
    open_ports: list[OpenPort] = field(default_factory=list)


def parse_ports(spec: str | None) -> list[int]:
    if not spec or spec.strip().lower() == "top":
        return list(TOP_PORTS)
    ports: set[int] = set()
    try:
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
                candidates = range(lo, hi + 1)
            else:
                candidates = [int(part)]
            for p in candidates:
                if not 1 <= p <= 65535:
                    raise ValueError
                ports.add(p)
            if len(ports) > MAX_PORTS:
                raise ValueError
    except ValueError:
        raise ValueError(
            f"Invalid port specification (use 'top', '22,80' or '1-1024'; max {MAX_PORTS} ports)"
        ) from None
    if not ports:
        raise ValueError("No ports specified")
    return sorted(ports)


def expand_targets(target: str, allow_public: bool = False) -> list[str]:
    target = (target or "").strip()
    if not target:
        raise TargetNotAllowed("Empty target")
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        try:
            infos = socket.getaddrinfo(target, None, socket.AF_INET)
        except socket.gaierror:
            raise TargetNotAllowed(f"Cannot resolve '{target}'") from None
        net = ipaddress.ip_network(infos[0][4][0])
    if net.version != 4:
        raise TargetNotAllowed("Only IPv4 is supported")
    if net.prefixlen < 24:
        raise TargetNotAllowed("Network too large: use a /24 or smaller")
    hosts = list(net) if net.num_addresses <= 2 else list(net.hosts())
    if not allow_public:
        for h in hosts:
            if not (h.is_private or h.is_loopback or h.is_link_local):
                raise TargetNotAllowed(
                    f"{h} is a public address. Public scanning is disabled; "
                    "only scan private networks you own or are authorised to test."
                )
    return [str(h) for h in hosts]


def _clean(data: bytes) -> str | None:
    text = data.decode("utf-8", "replace")
    text = "".join(c if (c.isprintable() or c in "\r\n") else "?" for c in text)
    text = text.strip()[:300]
    return text or None


async def _probe(ip: str, port: int, timeout: float, sem: asyncio.Semaphore) -> OpenPort | None:
    async with sem:
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        except (asyncio.TimeoutError, OSError):
            return None
        latency = (time.perf_counter() - start) * 1000
        banner = None
        try:
            if port in HTTP_PORTS:
                writer.write(b"HEAD / HTTP/1.0\r\nUser-Agent: NetGuardAI\r\n\r\n")
                await writer.drain()
            banner = _clean(await asyncio.wait_for(reader.read(512), BANNER_TIMEOUT))
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        return OpenPort(port, banner, round(latency, 1))


async def scan_network(
    ips: list[str], ports: list[int], timeout: float = 0.8, concurrency: int = 400
) -> list[HostScan]:
    if len(ips) * len(ports) > MAX_PROBES:
        raise ValueError(f"Too many probes (max {MAX_PROBES}); reduce hosts or ports")
    sem = asyncio.Semaphore(concurrency)
    jobs = [(ip, _probe(ip, p, timeout, sem)) for ip in ips for p in ports]
    results = await asyncio.gather(*(j for _, j in jobs))
    by_host: dict[str, list[OpenPort]] = {}
    for (ip, _), res in zip(jobs, results):
        if res:
            by_host.setdefault(ip, []).append(res)
    return [HostScan(ip, sorted(ps, key=lambda x: x.port)) for ip, ps in by_host.items()]


def local_cidr() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except OSError:
        return "127.0.0.1"
