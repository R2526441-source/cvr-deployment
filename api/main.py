# ============================================================
# main.py — CVR FastAPI application
# Endpoints:
#   GET  /           → health check
#   POST /score      → score one CVE with enterprise context
#   POST /batch      → score multiple CVEs at once
#   GET  /epss/{id}  → live EPSS lookup
# ============================================================
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import List, Optional
import time

from scorer import score_cve, fetch_epss, fetch_kev

app = FastAPI(
    title="CVR — Contextual Vulnerability Ranking API",
    description=(
        "Real-time vulnerability prioritisation for resource-constrained "
        "enterprises. Fuses global exploit intelligence (NVD, EPSS, KEV) "
        "with localised enterprise context via a stacking ML ensemble."
    ),
    version="1.0.0",
)

# Allow Streamlit dashboard to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request / Response schemas ────────────────────────────────
class CVRRequest(BaseModel):
    cve_id: str = Field(..., example="CVE-2023-44487",
                        description="CVE identifier")
    AC: int = Field(..., ge=1, le=6,
                    description="Asset Criticality (1=low → 6=mission-critical)")
    NE: int = Field(..., ge=0, le=2,
                    description="Network Exposure (0=air-gapped, 1=behind firewall, 2=internet-facing)")
    TA: float = Field(..., ge=0, le=15,
                      description="Technology Age in years")
    CM: int = Field(..., ge=1, le=5,
                    description="Change Management maturity (1=ad-hoc → 5=formal CAB)")
    RO: int = Field(..., ge=0, le=1,
                    description="Regulatory Obligation (0=none, 1=regulated)")

    @validator("cve_id")
    def validate_cve(cls, v):
        if not v.upper().startswith("CVE-"):
            raise ValueError("cve_id must start with CVE-")
        return v.upper()

class BatchRequest(BaseModel):
    items: List[CVRRequest]

# ── Endpoints ─────────────────────────────────────────────────
@app.get("/", tags=["Health"])
def root():
    return {
        "status"  : "online",
        "service" : "CVR Vulnerability Prioritisation API",
        "version" : "1.0.0",
        "docs"    : "/docs",
    }

@app.post("/score", tags=["Scoring"])
def score_single(req: CVRRequest):
    """
    Score a single CVE with enterprise context.
    Fetches live NVD, EPSS, and KEV data in real time.
    Returns CVR priority score, label, and key drivers.
    """
    t0 = time.time()
    try:
        result = score_cve(
            req.cve_id, req.AC, req.NE,
            req.TA, req.CM, req.RO
        )
        result["latency_ms"] = round((time.time() - t0) * 1000, 1)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/batch", tags=["Scoring"])
def score_batch(req: BatchRequest):
    """
    Score multiple CVEs in one request.
    Results are sorted by CVR score descending (highest risk first).
    """
    t0 = time.time()
    results = []
    for item in req.items:
        try:
            r = score_cve(item.cve_id, item.AC,
                          item.NE, item.TA, item.CM, item.RO)
            results.append(r)
        except Exception as e:
            results.append({"cve_id": item.cve_id, "error": str(e)})

    results.sort(key=lambda x: x.get("cvr_score", 0), reverse=True)
    return {
        "count"      : len(results),
        "latency_ms" : round((time.time() - t0) * 1000, 1),
        "results"    : results,
    }

@app.get("/epss/{cve_id}", tags=["Enrichment"])
def get_epss(cve_id: str):
    """Live EPSS score lookup for a single CVE."""
    return fetch_epss(cve_id.upper())

@app.get("/kev/{cve_id}", tags=["Enrichment"])
def get_kev(cve_id: str):
    """Check if a CVE is in the CISA KEV catalogue."""
    return {"cve_id": cve_id.upper(),
            "kev_confirmed": bool(fetch_kev(cve_id.upper()))}
