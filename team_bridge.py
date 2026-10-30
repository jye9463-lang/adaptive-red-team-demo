"""Read-only bridge to a teammate's AI execution API.

Credentials stay on the Render server and are never returned to the browser.
Only named upstream paths are permitted; no arbitrary URL proxying.
"""
import os
import re

import requests
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/team", tags=["Team AI engine (read-only)"])


def settings():
    base = os.getenv("TEAM_API_BASE_URL", "").strip().rstrip("/")
    token = os.getenv("TEAM_API_BEARER_TOKEN", "").strip()
    return base, token


def upstream_get(path):
    base, token = settings()
    if not base or not token:
        raise HTTPException(
            status_code=503,
            detail="팀원 API 환경 변수 TEAM_API_BASE_URL / TEAM_API_BEARER_TOKEN이 설정되지 않았습니다.",
        )
    if not base.startswith("https://"):
        raise HTTPException(status_code=503, detail="팀원 API URL은 HTTPS여야 합니다.")
    try:
        response = requests.get(
            base + path,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=(5, 15),
            allow_redirects=False,
        )
    except requests.RequestException:
        raise HTTPException(
            status_code=502,
            detail="팀원 AI 서버에 접속할 수 없습니다. Render에서 접근 가능한 공개 HTTPS 주소인지 확인하세요.",
        )
    if response.status_code in (301, 302, 303, 307, 308):
        raise HTTPException(status_code=502, detail="팀원 API가 리다이렉트했습니다. 서버 URL을 확인하세요.")
    if response.status_code in (401, 403):
        raise HTTPException(status_code=502, detail="팀원 서버 인증이 실패했습니다. 서버의 Bearer 토큰을 확인하세요.")
    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"팀원 서버에서 HTTP {response.status_code} 오류가 발생했습니다.")
    try:
        return response.json()
    except ValueError:
        raise HTTPException(status_code=502, detail="팀원 서버가 JSON 데이터를 반환하지 않았습니다.")


@router.get("/status")
def team_status():
    base, token = settings()
    if not (base and token):
        return {"configured": False, "reachable": False, "message": "팀원 API 환경 변수 미설정"}
    try:
        upstream_get("/health")
        return {"configured": True, "reachable": True, "message": "팀원 AI 서버에 연결되었습니다."}
    except HTTPException as exc:
        return {"configured": True, "reachable": False, "message": exc.detail}


@router.get("/models")
def team_models():
    return upstream_get("/models")


@router.get("/scenarios")
def team_scenarios():
    return upstream_get("/scenarios")


@router.get("/executions")
def team_executions():
    return upstream_get("/executions")


def validate_execution_id(execution_id):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", execution_id):
        raise HTTPException(status_code=422, detail="잘못된 execution_id입니다.")
    return execution_id


@router.get("/executions/{execution_id}")
def team_execution(execution_id: str):
    return upstream_get(f"/executions/{validate_execution_id(execution_id)}")


@router.get("/executions/{execution_id}/logs")
def team_execution_logs(execution_id: str):
    return upstream_get(f"/executions/{validate_execution_id(execution_id)}/logs")


@router.get("/executions/{execution_id}/report")
def team_execution_report(execution_id: str):
    return upstream_get(f"/executions/{validate_execution_id(execution_id)}/report")
