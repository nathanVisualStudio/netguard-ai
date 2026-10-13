import os
import secrets
import time
import uuid
from collections import OrderedDict

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field

from .analyzer import analyze_network
from .report import build_pdf
from .scanner import TargetNotAllowed, expand_targets, local_cidr, parse_ports, scan_network

ALLOW_PUBLIC = os.getenv("NETGUARD_ALLOW_PUBLIC") == "1"
TOKEN = os.getenv("NETGUARD_TOKEN", "")
MAX_REPORTS = 20
REPORTS: OrderedDict[str, dict] = OrderedDict()


def require_token(x_token: str = Header(default="")):
    if not TOKEN or not secrets.compare_digest(x_token.encode(), TOKEN.encode()):
        raise HTTPException(status_code=401, detail="Unauthorized")


app = FastAPI(title="NetGuard AI service", version="1.0.0", dependencies=[Depends(require_token)])
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class ScanRequest(BaseModel):
    target: str = Field(..., examples=["192.168.1.0/24"])
    ports: str = "top"
    timeout: float = Field(0.8, ge=0.2, le=5)


@app.get("/api/health")
def health():
    return {"status": "ok", "public_scanning": ALLOW_PUBLIC}


@app.get("/api/local-network")
def local_network():
    return {"cidr": local_cidr()}


@app.post("/api/scan")
async def scan(req: ScanRequest):
    try:
        ips = expand_targets(req.target, allow_public=ALLOW_PUBLIC)
        ports = parse_ports(req.ports)
        start = time.perf_counter()
        results = await scan_network(ips, ports, timeout=req.timeout)
    except TargetNotAllowed as e:
        raise HTTPException(status_code=400, detail=str(e)) from None
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from None
    report = analyze_network(req.target, len(ips), results, time.perf_counter() - start)
    report["id"] = uuid.uuid4().hex
    REPORTS[report["id"]] = report
    while len(REPORTS) > MAX_REPORTS:
        REPORTS.popitem(last=False)
    return report


@app.get("/api/report/{report_id}/pdf")
def report_pdf(report_id: str):
    report = REPORTS.get(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return Response(
        build_pdf(report),
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="netguard-report.pdf"'},
    )
