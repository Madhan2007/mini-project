import uuid
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from config.database import supabase
from services.request_cache import recall

router = APIRouter(prefix="/reports", tags=["Reports"])


class ReportRequest(BaseModel):
    request_id: Optional[str] = None
    reason: Optional[str] = None


@router.post("/")
@router.post("")
async def submit_report(payload: ReportRequest):
    ref = recall(payload.request_id or "")
    stored = False
    detail = "Report received."

    vpa = ref.get("vpa")
    if supabase and vpa:
        try:
            found = supabase.table("vpas").select("id").eq("vpa_normalized", vpa).execute()
            if found.data:
                vpa_id = found.data[0]["id"]
            else:
                vpa_id = supabase.table("vpas").insert(
                    {"vpa_normalized": vpa, "trusted_record": False}).execute().data[0]["id"]
            row = {"vpa_id": vpa_id, "reason": payload.reason, "request_id": payload.request_id}
            try:
                supabase.table("reports").insert(row).execute()
            except Exception:
                # extra columns not created yet (see schema.sql): store the bare report
                supabase.table("reports").insert({"vpa_id": vpa_id}).execute()
            stored = True
            detail = f"Report saved for {vpa}."
        except Exception as e:
            print("REPORT SAVE ERROR:", e)
    elif not vpa:
        detail = "Report received (nothing to link to a payee)."

    return {"status": "ok", "stored": stored, "detail": detail, "report_id": str(uuid.uuid4())}
