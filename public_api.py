"""Internet-facing FastAPI wrapper using an API key for all benchmark endpoints."""
import os
import secrets

from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from backend import app


@app.middleware("http")
async def require_api_token(request: Request, call_next):
    public_paths = {"/", "/health", "/docs", "/openapi.json"}
    if request.url.path not in public_paths:
        expected = os.environ.get("ADAPTIVE_API_TOKEN", "")
        supplied = request.headers.get("X-API-Key", "")
        if not expected or not secrets.compare_digest(supplied, expected):
            return JSONResponse(status_code=401, content={"detail": "API key required"})
    return await call_next(request)


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/openapi.json", include_in_schema=False)
def public_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
    schema.setdefault("components", {}).setdefault("securitySchemes", {})["ApiKeyAuth"] = {
        "type": "apiKey", "in": "header", "name": "X-API-Key",
        "description": "Render environment variable ADAPTIVE_API_TOKEN. Do not share this key publicly.",
    }
    for route, methods in schema.get("paths", {}).items():
        if route in {"/", "/health"}:
            continue
        for meta in methods.values():
            if isinstance(meta, dict):
                meta["security"] = [{"ApiKeyAuth": []}]
    app.openapi_schema = schema
    return schema


@app.get("/docs", include_in_schema=False)
def docs():
    return get_swagger_ui_html(openapi_url="/openapi.json", title="Adaptive Red Team API")
