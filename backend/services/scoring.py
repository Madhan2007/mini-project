"""Risk scoring for QR/VPA scans and screenshot (payment-proof) scans."""
from typing import Dict, List, Tuple

from config.schemas import ScanResponseEnvelope, Signal

# Human-readable text for the signal codes produced by calculate_risk_score()
SIGNAL_MESSAGES: Dict[str, Tuple[str, str]] = {
    "VERIFIED_MERCHANT": ("info", "Payee is a verified merchant in our records."),
    "UNKNOWN_PAYEE": ("caution", "We have no record of this payee. Verify before paying."),
    "REPORTED_BY_USERS": ("high", "This payee has been reported as fraudulent."),
    "COLLECT_REQUEST": ("high", "This is a collect request: approving it takes money OUT of your account."),
}


def calculate_risk_score(is_verified: bool, report_count: int, txn_type: str) -> Tuple[int, str, List[str]]:
    """Returns (score 0-100, verdict, [signal codes])."""
    score = 60
    signals: List[str] = []

    if is_verified:
        score += 35
        signals.append("VERIFIED_MERCHANT")
    else:
        signals.append("UNKNOWN_PAYEE")

    if report_count > 0:
        score -= min(80, 40 * report_count)
        signals.append("REPORTED_BY_USERS")

    if (txn_type or "pay").lower() == "collect":
        score -= 60
        signals.append("COLLECT_REQUEST")

    score = max(0, min(100, score))
    verdict = "green" if score >= 70 else ("yellow" if score >= 40 else "red")
    return score, verdict, signals


# ---------------------------------------------------------------- screenshots
_SEVERITY_MAP = {"success": "info", "info": "info", "warning": "caution",
                 "caution": "caution", "danger": "high", "high": "high"}

_ELA_MESSAGES = {
    "ELA_ANOMALY": ("high", "Image shows strong signs of editing or re-compression."),
    "ELA_SUSPICIOUS": ("caution", "Image shows mild signs of editing."),
}


def _norm_sev(sev: str) -> str:
    return _SEVERITY_MAP.get((sev or "info").lower(), "info")


def score_screenshot(forensics: dict, req_id: str) -> ScanResponseEnvelope:
    """Turn the raw output of forensics.analyze_payment_proof() into an envelope."""
    provider_status = {"llm": "bypassed", "forensics": "ok"}

    if forensics.get("status") != "SUCCESS":
        provider_status["forensics"] = "error"
        return ScanResponseEnvelope(
            request_id=req_id, scanner="screenshot", verdict="unable_to_verify", safety_score=50,
            explanation="We could not analyze this image.",
            signals=[Signal(code="ANALYSIS_FAILED", severity="caution",
                            message=forensics.get("error", "Image could not be processed."))],
            recommended_actions=["Upload a clearer image."],
            provider_status=provider_status, can_report=False)

    score = 95
    signals: List[Signal] = []
    seen = set()

    def add(code: str, sev: str, msg: str):
        if code not in seen:
            seen.add(code)
            signals.append(Signal(code=code, severity=_norm_sev(sev), message=msg))

    for s in forensics.get("signals", []):
        code = s.get("code", "UNKNOWN")
        add(code, s.get("severity", "info"), s.get("message") or code.replace("_", " ").capitalize())
        if code == "AMOUNT_MISMATCH":
            score -= 40

    ela = float(forensics.get("ela_anomaly_score", 0) or 0)
    if ela > 45:
        score -= 60
        add("ELA_ANOMALY", *_ELA_MESSAGES["ELA_ANOMALY"])
    elif ela > 30:
        score -= 20
        add("ELA_SUSPICIOUS", *_ELA_MESSAGES["ELA_SUSPICIOUS"])

    score = max(0, min(100, score))
    verdict = "green" if score >= 70 else ("yellow" if score >= 40 else "red")
    if not signals:
        add("NO_RED_FLAGS", "info", "No signs of tampering found.")

    actions = {
        "green": ["Looks consistent, but always confirm the money arrived in your bank app."],
        "yellow": ["Confirm the payment in your bank app before handing over goods."],
        "red": ["Do not trust this receipt.", "Check your bank app directly and report the sender."],
    }[verdict]
    explanation = {
        "green": "This image shows no strong signs of tampering.",
        "yellow": "This image has some suspicious traits. Verify in your bank app.",
        "red": "This image looks edited or forged. Do not accept it as proof of payment.",
    }[verdict]

    return ScanResponseEnvelope(
        request_id=req_id, scanner="screenshot", verdict=verdict, safety_score=score,
        explanation=explanation, signals=signals, recommended_actions=actions,
        provider_status=provider_status, can_report=verdict != "green")
