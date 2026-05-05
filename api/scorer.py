# ============================================================
# scorer.py — CVR scoring engine
# Handles live data enrichment + model inference
# ============================================================
import requests, joblib, json, os
import pandas as pd
import numpy as np

# ── Load artefacts once at startup ───────────────────────────
BASE_DIR   = os.path.dirname(__file__)
MODEL      = joblib.load(os.path.join(BASE_DIR, "cvr_model_compressed.pkl"))
SCALER     = joblib.load(os.path.join(BASE_DIR, "scaler.pkl"))
with open(os.path.join(BASE_DIR, "feature_columns.json")) as f:
    FEATURE_COLS = json.load(f)

# ── CVSS severity normalisation map ──────────────────────────
SEVERITY_ORDER = {"NONE":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}

def fetch_nvd(cve_id: str) -> dict:
    """Fetch CVE metadata from NVD API."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        items = r.json().get("vulnerabilities", [])
        if not items:
            return {}
        cve = items[0]["cve"]
        metrics = cve.get("metrics", {})
        cvss = {}
        for key in ["cvssMetricV31","cvssMetricV30"]:
            if metrics.get(key):
                m = metrics[key][0].get("cvssData", {})
                cvss = {
                    "cvss_base_score"        : m.get("baseScore", 5.0),
                    "cvss_base_severity"     : m.get("baseSeverity","MEDIUM"),
                    "cvss_attack_vector"     : m.get("attackVector","NETWORK"),
                    "cvss_attack_complexity" : m.get("attackComplexity","LOW"),
                    "cvss_privs_required"    : m.get("privilegesRequired","NONE"),
                    "cvss_user_interaction"  : m.get("userInteraction","NONE"),
                    "cvss_scope"             : m.get("scope","UNCHANGED"),
                    "cvss_conf_impact"       : m.get("confidentialityImpact","NONE"),
                    "cvss_integ_impact"      : m.get("integrityImpact","NONE"),
                    "cvss_avail_impact"      : m.get("availabilityImpact","NONE"),
                }
                break

        # PoC detection
        refs = cve.get("references",[])
        poc_sources = {"exploit-db.com","github.com",
                       "metasploit.com","packetstormsecurity.com"}
        poc_available = int(any(
            any(s in ref.get("url","").lower() for s in poc_sources)
            for ref in refs
        ))

        # CWE
        weaknesses = cve.get("weaknesses",[])
        cwe_id = ""
        if weaknesses:
            d = weaknesses[0].get("description",[])
            if d: cwe_id = d[0].get("value","")

        return {**cvss, "poc_available": poc_available, "cwe_id": cwe_id}
    except Exception:
        return {}

def fetch_epss(cve_id: str) -> dict:
    """Fetch current EPSS score from FIRST API."""
    try:
        r = requests.get(
            f"https://api.first.org/data/1.0/epss?cve={cve_id}",
            timeout=10
        )
        data = r.json().get("data",[])
        if data:
            return {
                "epss_score"      : float(data[0].get("epss",0)),
                "epss_percentile" : float(data[0].get("percentile",0)),
            }
    except Exception:
        pass
    return {"epss_score": 0.0, "epss_percentile": 0.0}

def fetch_kev(cve_id: str) -> int:
    """Check if CVE is in CISA KEV catalogue."""
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json",
            timeout=10
        )
        ids = [v["cveID"] for v in r.json().get("vulnerabilities",[])]
        return int(cve_id in ids)
    except Exception:
        return 0

def build_feature_row(cve_id:str, AC:int, NE:int,
                       TA:float, CM:int, RO:int) -> pd.DataFrame:
    """
    Assemble one feature row matching training feature space.
    Fetches live global signals; uses analyst-provided context.
    """
    nvd  = fetch_nvd(cve_id)
    epss = fetch_epss(cve_id)
    kev  = fetch_kev(cve_id)

    # ── Build raw record ──────────────────────────────────────
    raw = {
        "cvss_base_score"        : nvd.get("cvss_base_score", 5.0),
        "cvss_exploit_score"     : 0.0,   # removed by VIF — placeholder
        "cvss_impact_score"      : 0.0,   # removed by VIF — placeholder
        "epss_score"             : epss["epss_score"],
        "epss_percentile"        : epss["epss_percentile"],
        "kev_included"           : kev,
        "poc_available"          : nvd.get("poc_available", 0),
        "AC"                     : AC,
        "NE"                     : NE,
        "TA"                     : float(TA),
        "WITHIN_SUPPORT"         : int(TA <= 7),   # heuristic: >7yr → likely EOL
        "CM"                     : CM,
        "RO"                     : RO,
    }

    # ── One-hot encode CVSS categoricals ─────────────────────
    NOMINAL_FIELDS = {
        "cvss_base_severity"     : ["NONE","LOW","MEDIUM","HIGH","CRITICAL"],
        "cvss_attack_vector"     : ["LOCAL","ADJACENT_NETWORK",
                                    "NETWORK","PHYSICAL"],
        "cvss_attack_complexity" : ["LOW","HIGH"],
        "cvss_privs_required"    : ["NONE","LOW","HIGH"],
        "cvss_user_interaction"  : ["NONE","REQUIRED"],
        "cvss_scope"             : ["UNCHANGED","CHANGED"],
        "cvss_conf_impact"       : ["NONE","LOW","HIGH"],
        "cvss_integ_impact"      : ["NONE","LOW","HIGH"],
        "cvss_avail_impact"      : ["NONE","LOW","HIGH"],
        "cwe_id"                 : ["OTHER"],   # collapsed
    }
    for field, categories in NOMINAL_FIELDS.items():
        val = nvd.get(field, categories[0])
        if field == "cwe_id":
            val = val if val in FEATURE_COLS else "OTHER"
        for cat in categories:
            col = f"{field}_{cat}"
            raw[col] = int(val == cat)

    # ── Align to training feature space ──────────────────────
    row = pd.DataFrame([raw])
    for col in FEATURE_COLS:
        if col not in row.columns:
            row[col] = 0
    row = row[FEATURE_COLS]   # exact column order

    # ── Scale ─────────────────────────────────────────────────
    row_scaled = pd.DataFrame(
        SCALER.transform(row),
        columns=FEATURE_COLS
    )
    return row_scaled, raw, epss, kev

def score_cve(cve_id:str, AC:int, NE:int,
              TA:float, CM:int, RO:int) -> dict:
    """Full scoring pipeline for one CVE."""
    row, raw, epss, kev = build_feature_row(
        cve_id, AC, NE, TA, CM, RO
    )
    prob  = float(MODEL.predict_proba(row)[0][1])
    pred  = int(MODEL.predict(row)[0])
    label = "URGENT" if pred == 1 else "DEFER"

    # ── Human-readable explanation ────────────────────────────
    drivers = []
    if raw.get("poc_available"): drivers.append("PoC exploit available")
    if kev:                       drivers.append("CISA KEV confirmed exploitation")
    if epss["epss_score"] > 0.10: drivers.append(f"High EPSS ({epss['epss_score']:.3f})")
    if AC >= 5:                   drivers.append("Mission-critical asset (AC=5+)")
    if NE == 2:                   drivers.append("Internet-facing exposure")
    if not raw.get("WITHIN_SUPPORT"): drivers.append("System outside vendor support")

    return {
        "cve_id"          : cve_id,
        "cvr_score"       : round(prob, 4),
        "priority"        : pred,
        "priority_label"  : label,
        "epss_score"      : round(epss["epss_score"], 4),
        "epss_percentile" : round(epss["epss_percentile"], 4),
        "kev_confirmed"   : bool(kev),
        "poc_available"   : bool(raw.get("poc_available")),
        "cvss_score"      : raw.get("cvss_base_score"),
        "cvss_severity"   : raw.get("cvss_base_severity_HIGH") and "HIGH" or "MEDIUM",
        "context"         : {"AC":AC,"NE":NE,"TA":TA,"CM":CM,"RO":RO},
        "key_drivers"     : drivers if drivers else ["Moderate global signals — deferral recommended"],
    }
