"""Authenticated, controlled bridge to the team's AI orchestrator.

Request contract based on teammate's OpenAPI 3.1, version 0.2.0.
Only MOCK execution is exposed from the public backend. No real targets/scans.
The upstream Bearer token remains in Render server environment variables.
"""
import os
import re
from typing import Literal

import requests
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, ConfigDict, model_validator

router = APIRouter(prefix="/team", tags=["Team AI orchestrator"])


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str = Field(min_length=1, max_length=150)
    role: str = Field(default="access-control tester", min_length=1, max_length=300)
    prompt_version: Literal["v1"] = "v1"
    instructions: str = Field(default="", max_length=1500)


class Budget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seconds: float = Field(default=60, ge=0.05, le=300)
    requests: int = Field(default=12, ge=1, le=50)
    model_calls: int = Field(default=12, ge=1, le=30)
    tokens: int = Field(default=100000, ge=100, le=1000000)
    max_output_tokens: int = Field(default=1000, ge=100, le=4000)
    cost_usd: float | None = Field(default=None, gt=0, le=10)


class MockExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["mock"] = "mock"
    scenario: Literal["orders-v1", "web-access-v1"] = "orders-v1"
    target_id: str | None = Field(default=None, min_length=1, max_length=100)
    environment: Literal["vulnerable", "fixed"] = "vulnerable"
    collaboration: Literal["independent"] = "independent"
    information: Literal["gray-box"] = "gray-box"
    tools: list[Literal["http"]] = Field(default_factory=lambda: ["http"], min_length=1, max_length=1)
    state_changes: Literal[False] = False
    agents: list[AgentConfig] = Field(min_length=2, max_length=3)
    budget: Budget = Field(default_factory=Budget)

    @model_validator(mode="after")
    def distinct_models(self):
        model_names = [a.model for a in self.agents]
        if len(model_names) != len(set(model_names)):
            raise ValueError("같은 모델을 두 번 선택할 수 없습니다.")
        return self


def settings():
    return (os.getenv("TEAM_API_BASE_URL", "").strip().rstrip("/"),
            os.getenv("TEAM_API_BEARER_TOKEN", "").strip())


def upstream(method: str, path: str, *, params=None, payload=None):
    base, token = settings()
    if not base or not token:
        raise HTTPException(
            status_code=503,
            detail="Render의 TEAM_API_BASE_URL 및 TEAM_API_BEARER_TOKEN 설정이 필요합니다.",
        )
    if not base.startswith("https://"):
        raise HTTPException(status_code=503, detail="팀원 서버 URL은 HTTPS여야 합니다.")
    try:
        response = requests.request(
            method, base + path,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            params=params, json=payload,
            timeout=(5, 25), allow_redirects=False,
        )
    except requests.RequestException:
        raise HTTPException(
            status_code=502,
            detail="팀원 AI 서버에 연결하지 못했습니다. Render 서버에서 접속 가능한 주소인지 확인하세요.",
        )
    if response.status_code in (301, 302, 303, 307, 308):
        raise HTTPException(status_code=502, detail="팀원 API 리다이렉트 발생: 서버 URL을 확인하세요.")
    if response.status_code in (401, 403):
        raise HTTPException(status_code=502, detail="팀원 서버의 Bearer 인증에 실패했습니다.")
    if response.status_code >= 400:
        # The upstream error body can contain sensitive details. Do not leak it.
        raise HTTPException(status_code=502, detail=f"팀원 서버에서 HTTP {response.status_code} 오류가 발생했습니다.")
    try:
        return response.json()
    except ValueError:
        raise HTTPException(status_code=502, detail="팀원 서버가 JSON을 반환하지 않았습니다.")


def validate_execution_id(execution_id: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", execution_id):
        raise HTTPException(status_code=422, detail="올바르지 않은 실행 ID입니다.")
    return execution_id


@router.get("/status")
def team_status():
    base, token = settings()
    if not (base and token):
        return {"configured": False, "reachable": False, "message": "팀원 서버 연결 설정이 없습니다."}
    try:
        upstream("GET", "/health")
        return {"configured": True, "reachable": True, "message": "팀원 AI 서버 연결 성공"}
    except HTTPException as exc:
        return {"configured": True, "reachable": False, "message": exc.detail}


@router.get("/models")
def team_models():
    return upstream("GET", "/models")


@router.get("/scenarios")
def team_scenarios():
    return upstream("GET", "/scenarios")


@router.post("/executions", status_code=202)
def create_mock_execution(payload: MockExecutionRequest):
    """Create an authorized MOCK execution. LIVE mode is intentionally blocked."""
    return upstream("POST", "/executions", payload=payload.model_dump(exclude_none=True))


@router.get("/executions")
def team_executions(limit: int = Query(default=20, ge=1, le=100),
                    offset: int = Query(default=0, ge=0)):
    return upstream("GET", "/executions", params={"limit": limit, "offset": offset})


@router.get("/executions/{execution_id}")
def team_execution(execution_id: str):
    return upstream("GET", f"/executions/{validate_execution_id(execution_id)}")


@router.get("/executions/{execution_id}/logs")
def team_execution_logs(execution_id: str, after: int = Query(default=0, ge=0),
                        limit: int = Query(default=100, ge=1, le=500)):
    return upstream("GET", f"/executions/{validate_execution_id(execution_id)}/logs",
                    params={"after": after, "limit": limit})


@router.get("/executions/{execution_id}/report")
def team_execution_report(execution_id: str):
    return upstream("GET", f"/executions/{validate_execution_id(execution_id)}/report")


@router.post("/executions/{execution_id}/cancel")
def cancel_team_execution(execution_id: str):
    return upstream("POST", f"/executions/{validate_execution_id(execution_id)}/cancel")
