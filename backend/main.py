import os
import sys
import uuid

# Ensure backend directory is in sys.path for serverless runtimes (like Vercel)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from routers import scan_qr, scan_url, scan_text, reports

app = FastAPI(
    title="ScamShield AI API",
    description="Pre-payment risk scoring and multimodal threat analysis engine",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.get("/healthz", tags=["System"])
async def healthz():
    return {"status": "ok"}


@app.get("/readyz", tags=["System"])
async def readyz():
    return {"status": "ready"}


app.include_router(scan_qr.router, prefix="/api/v1")
app.include_router(scan_url.router, prefix="/api/v1")
app.include_router(scan_text.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")

# The screenshot scanner needs heavy optional packages (opencv, easyocr).
# If they are missing, the rest of the API still starts normally.
try:
    from routers import scan_screenshot
    app.include_router(scan_screenshot.router, prefix="/api/v1")
except Exception as e:  # pragma: no cover
    print(f"⚠️  Screenshot scanner disabled: {e}")
    print("    Install with: pip install opencv-python-headless numpy pillow easyocr")
