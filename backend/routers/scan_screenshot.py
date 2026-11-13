import uuid
from typing import Optional

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Request

from services.forensics import analyze_payment_proof
from services.scoring import score_screenshot
from services.request_cache import remember

router = APIRouter(prefix="/scan", tags=["Screenshot Scanner"])

IMAGE_EXT = (".png", ".jpg", ".jpeg", ".webp", ".heic", ".bmp")


@router.post("/screenshot")
async def process_screenshot(
    request: Request,
    file: UploadFile = File(...),
    expected_amount: Optional[float] = Form(None),
):
    ctype = (file.content_type or "").lower()
    name = (file.filename or "").lower()
    if not (ctype.startswith("image/") or name.endswith(IMAGE_EXT)):
        raise HTTPException(status_code=400, detail="File must be an image.")

    req_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    remember(req_id, kind="screenshot", value=file.filename)

    try:
        image_bytes = await file.read()
        forensics_data = analyze_payment_proof(image_bytes, expected_amount)
        return score_screenshot(forensics_data, req_id)
    except Exception as e:
        print(f"Screenshot error: {e}")
        return {
            "request_id": req_id,
            "scanner": "screenshot",
            "verdict": "unable_to_verify",
            "safety_score": 50,
            "explanation": "Critical error processing image.",
            "signals": [],
            "recommended_actions": ["Upload a clearer image."],
            "provider_status": {"llm": "bypassed", "forensics": "error"},
            "can_report": False,
        }
