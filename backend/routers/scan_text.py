import re
import uuid
from typing import Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel

from config.schemas import ScanResponseEnvelope, Signal
from services.explainer import generate_explanation
from services.request_cache import remember

router = APIRouter(prefix="/scan", tags=["Message Scanner"])


class TextScanRequest(BaseModel):
    text: Optional[str] = None


# (code, severity, message, penalty, regex)
RULES = [
    ("URGENCY", "caution", "Message pressures you to act right now.", 15,
     r"\b(immediately|urgent|urgently|right now|within \d+ ?(hours?|hrs?|minutes?|mins?)|today only|last (warning|chance)|expires?( today)?|act now|final notice)\b"),
    ("THREAT", "high", "Message threatens disconnection, blocking or legal action.", 30,
     r"\b(power ?cut|disconnect(ed|ion)?|blocked|suspended|deactivated|legal action|arrest|fir\b|court|penalty|police|cbi|customs)\b"),
    ("SENSITIVE_INFO_REQUEST", "high", "Message asks for OTP, PIN, CVV or password. Real banks never ask for these.", 40,
     r"\b(otp|pin|cvv|password|card number|expiry date|net ?banking)\b"),
    ("KYC_SCAM", "high", "Fake KYC / Aadhaar / PAN update request.", 25,
     r"\b(kyc|aadhaar|aadhar|pan card|update your (account|kyc|pan))\b"),
    ("PRIZE_OR_REFUND_BAIT", "high", "Prize, lottery, cashback or refund bait.", 30,
     r"\b(lottery|you have won|you('ve| have) been selected|prize|jackpot|cashback|refund|reward points?|gift card)\b"),
    ("ADVANCE_FEE", "high", "Asks you to pay a fee or send money first.", 30,
     r"\b(processing fee|registration fee|security deposit|send (rs\.?|₹)?\s?\d+|transfer (rs\.?|₹)?\s?\d+|pay (rs\.?|₹)\s?\d+)"),
    ("REMOTE_ACCESS_APP", "high", "Asks you to install a remote-access app (AnyDesk, TeamViewer...).", 40,
     r"\b(anydesk|teamviewer|quicksupport|rustdesk|screen ?share)\b"),
    ("APK_INSTALL", "high", "Asks you to install an app file (APK).", 35, r"\.apk\b|install (the )?(app|apk)"),
    ("COLLECT_REQUEST_TRICK", "high", "Asks you to 'accept' or 'approve' a payment request to receive money. That sends money out.", 35,
     r"\b(accept (the )?(request|collect)|approve (the )?(request|collect)|enter (your )?upi pin to receive)\b"),
    ("SUSPICIOUS_LINK", "caution", "Message contains a link. Do not tap it before checking it.", 15,
     r"(https?://|www\.|\b(bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy)/)"),
    ("PHONE_NUMBER_CALLBACK", "caution", "Message asks you to call a number.", 10,
     r"\b(call|contact|whatsapp)\b.{0,40}\b(\+?91[\s-]?)?[6-9]\d{9}\b"),
]


def analyze_text(text: str):
    t = text.lower()
    score = 90
    sigs = []
    for code, sev, msg, pen, pattern in RULES:
        if re.search(pattern, t):
            sigs.append((code, sev, msg))
            score -= pen
    score = max(0, min(100, score))
    verdict = "green" if score >= 70 else ("yellow" if score >= 40 else "red")
    if not sigs:
        sigs.append(("NO_RED_FLAGS", "info", "No common scam patterns found in this message."))
    return score, verdict, sigs


@router.post("/text", response_model=ScanResponseEnvelope)
async def scan_text(payload: TextScanRequest, request: Request):
    req_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    if not payload.text or len(payload.text.strip()) < 5:
        return ScanResponseEnvelope(
            request_id=req_id, scanner="text", verdict="unable_to_verify", safety_score=50,
            explanation="The message is too short to analyze.",
            signals=[Signal(code="TEXT_TOO_SHORT", severity="caution", message="Not enough text to analyze.")],
            recommended_actions=["Paste the full message and try again."],
            provider_status="ok", can_report=False)

    score, verdict, sigs = analyze_text(payload.text)
    remember(req_id, kind="text", value=payload.text[:300])
    explanation = await generate_explanation(verdict, score, [c for c, _, _ in sigs])
    actions = {
        "green": ["Looks fine, but never share OTP, PIN or passwords."],
        "yellow": ["Do not click links or call numbers in the message.", "Contact the company using its official app or website."],
        "red": ["Do not reply, click links or share any codes.", "Block the sender and report the message."],
    }[verdict]
    return ScanResponseEnvelope(
        request_id=req_id, scanner="text", verdict=verdict, safety_score=score, explanation=explanation,
        signals=[Signal(code=c, severity=s, message=m) for c, s, m in sigs],
        recommended_actions=actions, provider_status="ok", can_report=True)
