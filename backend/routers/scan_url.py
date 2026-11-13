import re
import uuid
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Request
from pydantic import BaseModel

from config.schemas import ScanResponseEnvelope, Signal
from services.explainer import generate_explanation
from services.request_cache import remember

router = APIRouter(prefix="/scan", tags=["URL Scanner"])


class URLScanRequest(BaseModel):
    url: Optional[str] = None


SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "ow.ly"}
RISKY_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "loan", "zip", "mov", "buzz", "icu", "cyou"}
KEYWORDS = ["login", "verify", "kyc", "update", "secure", "refund", "reward", "claim", "prize", "bonus",
            "cashback", "suspend", "unlock", "account", "upi", "bank", "otp"]
# brand -> official registrable domains
BRANDS = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "gpay": ["pay.google.com"],
    "npci": ["npci.org.in"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "irctc": ["irctc.co.in"],
    "incometax": ["incometax.gov.in"],
}


def _registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "gov", "net", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_url(raw: str):
    """Returns (score, verdict, [(code, severity, message)]). Never opens the URL."""
    raw = raw.strip()
    url = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "http://" + raw
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    signals: List[tuple] = []
    score = 90

    if not host or "." not in host and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return 50, "unable_to_verify", [("MALFORMED_URL", "high", "This does not look like a valid link.")]

    def add(code, sev, msg, penalty):
        nonlocal score
        signals.append((code, sev, msg))
        score -= penalty

    if parsed.scheme == "http":
        add("NO_HTTPS", "caution", "Link does not use HTTPS encryption.", 15)
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        add("IP_ADDRESS_HOST", "high", "Link uses a raw IP address instead of a domain name.", 35)
    if "@" in parsed.netloc:
        add("AT_SYMBOL_IN_URL", "high", "Link contains '@', a trick used to hide the real destination.", 30)
    if "xn--" in host:
        add("PUNYCODE_DOMAIN", "high", "Domain uses look-alike (punycode) characters.", 30)
    if host in SHORTENERS:
        add("URL_SHORTENER", "caution", "Shortened link hides the real destination.", 20)

    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        add("RISKY_TLD", "caution", f"Domain ending '.{tld}' is commonly abused by scammers.", 20)
    if host.count(".") >= 4:
        add("MANY_SUBDOMAINS", "caution", "Unusually many subdomains.", 15)
    if host.count("-") >= 3:
        add("MANY_HYPHENS", "caution", "Domain contains many hyphens.", 10)
    if len(url) > 120:
        add("VERY_LONG_URL", "info", "Very long link.", 5)

    if path.endswith(".apk") or ".apk" in path:
        add("APK_DOWNLOAD", "high", "Link downloads an Android app file (APK) outside the Play Store.", 40)
    elif re.search(r"\.(exe|scr|bat|msi|jar)$", path):
        add("EXECUTABLE_DOWNLOAD", "high", "Link downloads an executable file.", 40)

    found = [k for k in KEYWORDS if k in host or k in path]
    if found:
        add("PHISHING_KEYWORDS", "caution", "Link contains words often used in phishing: " + ", ".join(found[:4]) + ".", min(25, 8 * len(found)))

    reg = _registrable(host)
    for brand, official in BRANDS.items():
        if brand in host and reg not in official:
            add("BRAND_IMPERSONATION", "high", f"Domain mentions '{brand}' but is not an official {brand} domain.", 40)
            break

    score = max(0, min(100, score))
    verdict = "green" if score >= 70 else ("yellow" if score >= 40 else "red")
    if not signals:
        signals.append(("NO_RED_FLAGS", "info", "No suspicious patterns found in the link structure."))
    return score, verdict, signals


@router.post("/url", response_model=ScanResponseEnvelope)
async def scan_url(payload: URLScanRequest, request: Request):
    req_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    if not payload.url or not payload.url.strip():
        return ScanResponseEnvelope(
            request_id=req_id, scanner="url", verdict="unable_to_verify", safety_score=50,
            explanation="No link was provided.",
            signals=[Signal(code="MALFORMED_URL", severity="high", message="Empty link.")],
            recommended_actions=["Paste the full link and try again."],
            provider_status="ok", can_report=False)

    score, verdict, sigs = analyze_url(payload.url)
    remember(req_id, kind="url", value=payload.url.strip())

    if verdict == "unable_to_verify":
        return ScanResponseEnvelope(
            request_id=req_id, scanner="url", verdict=verdict, safety_score=score,
            explanation="This does not look like a valid link.",
            signals=[Signal(code=c, severity=s, message=m) for c, s, m in sigs],
            recommended_actions=["Check the link and try again."],
            provider_status="ok", can_report=False)

    explanation = await generate_explanation(verdict, score, [c for c, _, _ in sigs])
    actions = {
        "green": ["No strong warning signs, but only enter details on sites you trust."],
        "yellow": ["Do not enter personal or banking details.", "Open the official site by typing its address yourself."],
        "red": ["Do not open this link or install anything from it.", "Report it as a scam."],
    }[verdict]
    return ScanResponseEnvelope(
        request_id=req_id, scanner="url", verdict=verdict, safety_score=score, explanation=explanation,
        signals=[Signal(code=c, severity=s, message=m) for c, s, m in sigs],
        recommended_actions=actions, provider_status="ok", can_report=True)
