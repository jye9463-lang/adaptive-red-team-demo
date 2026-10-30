from fastapi import FastAPI
from pydantic import BaseModel, Field
import sqlite3
import os
from pathlib import Path

# FastAPI 서버 생성
app = FastAPI(title="Adaptive Red Team: benchmark API", docs_url=None, redoc_url=None, openapi_url=None)

# 데이터베이스 파일 위치
DB_PATH = Path(os.environ.get("ADAPTIVE_DB_PATH", str(Path(__file__).with_name("experiments.db"))))


# 데이터베이스 초기 설정
def init_db():
    conn = sqlite3.connect(DB_PATH)

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS experiments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model TEXT NOT NULL,
                detection_rate REAL NOT NULL,
                execution_time REAL NOT NULL,
                api_cost REAL NOT NULL,
                is_sample INTEGER NOT NULL DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()

    finally:
        conn.close()


# 서버 시작 시 데이터베이스 준비
init_db()


# 저장할 데이터 형식
class Experiment(BaseModel):
    model: str = Field(min_length=1)
    detection_rate: float = Field(ge=0, le=100)
    execution_time: float = Field(ge=0)
    api_cost: float = Field(ge=0)
    is_sample: bool = True


# 서버 실행 확인
@app.get("/")
def home():
    return {
        "message": "Adaptive Red Team 서버 실행 성공!"
    }


# 기존 샘플 결과 제공
@app.get("/results")
def results():
    return {
        "sample_data": True,
        "models": [
            {"name": "GPT", "detection_rate": 60},
            {"name": "Claude", "detection_rate": 70},
            {"name": "GPT + Claude", "detection_rate": 90}
        ]
    }


# 새로운 실험 결과 저장
@app.post("/experiments")
def save_experiment(experiment: Experiment):

    conn = sqlite3.connect(DB_PATH)

    try:
        cursor = conn.execute(
            """
            INSERT INTO experiments
            (model, detection_rate, execution_time, api_cost, is_sample)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                experiment.model,
                experiment.detection_rate,
                experiment.execution_time,
                experiment.api_cost,
                int(experiment.is_sample)
            )
        )

        conn.commit()

        return {
            "message": "실험 결과 저장 성공!",
            "id": cursor.lastrowid
        }

    finally:
        conn.close()


# 저장된 실험 결과 조회
@app.get("/experiments")
def get_experiments():

    conn = sqlite3.connect(DB_PATH)

    try:
        conn.row_factory = sqlite3.Row

        cursor = conn.execute(
            "SELECT * FROM experiments ORDER BY id DESC"
        )

        experiments = [
            dict(row) for row in cursor.fetchall()
        ]

        return {
            "experiments": experiments
        }

    finally:
        conn.close()

# ======================================
# 5. AI 데모 테스트 및 실행 로그
# ======================================

import json
from fastapi import HTTPException


# 데모 테스트 데이터베이스 생성
def init_demo_db():
    conn = sqlite3.connect(DB_PATH)

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS demo_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                models TEXT NOT NULL,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                logs TEXT NOT NULL,
                findings TEXT NOT NULL,
                is_sample INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()

    finally:
        conn.close()


init_demo_db()


# 테스트 요청 데이터 형식
class DemoRunRequest(BaseModel):
    models: list[str] = Field(min_length=1)
    mode: str


# 데모 테스트 시작
@app.post("/demo-runs")
def start_demo_run(request: DemoRunRequest):

    allowed_models = {"GPT", "Claude", "Llama"}

    if any(model not in allowed_models for model in request.models):
        raise HTTPException(
            status_code=400,
            detail="지원하지 않는 AI 모델입니다."
        )

    # 샘플 실행 로그
    logs = [
        "테스트 요청 접수",
        "AI 모델 설정 확인",
        "샘플 분석 결과 생성",
        "샘플 결과 통합 완료",
        "데모 보고서 생성 완료"
    ]

    # 샘플 취약점 보고서
    findings = [
        {
            "name": "접근 권한 설정 미흡",
            "severity": "높음",
            "evidence": "데모용 가상 검증 근거",
            "recommendation": "사용자별 접근 권한을 점검하세요."
        },
        {
            "name": "민감 정보 노출 가능성",
            "severity": "중간",
            "evidence": "데모용 가상 검증 근거",
            "recommendation": "민감 정보 공개 여부를 확인하세요."
        }
    ]

    conn = sqlite3.connect(DB_PATH)

    try:
        cursor = conn.execute(
            """
            INSERT INTO demo_runs
            (models, mode, status, logs, findings)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                json.dumps(request.models, ensure_ascii=False),
                request.mode,
                "completed",
                json.dumps(logs, ensure_ascii=False),
                json.dumps(findings, ensure_ascii=False)
            )
        )

        conn.commit()

        return {
            "test_id": cursor.lastrowid,
            "status": "completed",
            "is_sample": True
        }

    finally:
        conn.close()


# 데모 테스트 결과 조회
@app.get("/demo-runs/{test_id}")
def get_demo_run(test_id: int):

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        row = conn.execute(
            "SELECT * FROM demo_runs WHERE id = ?",
            (test_id,)
        ).fetchone()

        if row is None:
            raise HTTPException(
                status_code=404,
                detail="테스트 결과가 없습니다."
            )

        result = dict(row)

        result["models"] = json.loads(result["models"])
        result["logs"] = json.loads(result["logs"])
        result["findings"] = json.loads(result["findings"])
        result["is_sample"] = bool(result["is_sample"])

        return result

    finally:
        conn.close()
from integration_api import router as integration_router
app.include_router(integration_router)        
from combo_eval_api import router as combo_router
app.include_router(combo_router)    
from combo_eval_api import seed_demo
seed_demo()
