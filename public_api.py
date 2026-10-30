"""Internet-facing wrapper for the evaluation API.
Only deploy the mock/authorized benchmark; access to benchmark data requires a token.
"""
import os
import secrets

from fastapi import Request
from fastapi.responses import JSONResponse
from backend import app

@app.middleware("http")
async def require_api_token(request: Request, call_next):
    public_paths = {"/", "/health", "/docs", "/openapi.json", "/redoc"}
    if request.url.path not in public_paths:
        expected = os.environ.get("ADAPTIVE_API_TOKEN", "")
        supplied = request.headers.get("X-API-Key", "")
        if not expected or not secrets.compare_digest(supplied, expected):
            return JSONResponse(status_code=401, content={"detail": "API key required"})
    return await call_next(request)

@app.get("/health")
def health():
    return {"ok": True}

# The existing backend disables docs for its internal Streamlit usage.
# Show API docs for deployed debugging; requests still require X-API-Key.
app.docs_url = "/docs"
app.openapi_url = "/openapi.json"
app.redoc_url = None
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

@app.get("/openapi.json", include_in_schema=False)
def public_openapi():
    return get_openapi(title=app.title, version=app.version, routes=app.routes)

@app.get("/docs", include_in_schema=False)
def docs():
    return get_swagger_ui_html(openapi_url="/openapi.json", title="Adaptive Red Team API")
