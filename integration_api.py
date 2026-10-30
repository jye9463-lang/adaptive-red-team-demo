"""Adaptive Red Team: team-result ingestion and evaluation for a demo fixture.

The fixture IDs below are synthetic. This router NEVER runs a security scan.
Use an authenticated wrapper (public_api.py) before exposing this router online.
"""
import json
import sqlite3
import os
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/integrations", tags=["AI Team Integration"])
DB_PATH = Path(os.environ.get("ADAPTIVE_DB_PATH", str(Path(__file__).with_name("experiments.db"))))

# For this step we use a known, FICTIONAL answer key. Replace with the test
# environment owner's verified ground truth before reporting real performance.
DEMO_GROUND_TRUTH = {
    "demo-lab-01": {"LAB-001", "LAB-002", "LAB-003"}
}
ALLOWED_MODELS = {"GPT", "Claude", "Llama"}


class AIResult(BaseModel):
    target_id: str = Field(default="demo-lab-01", min_length=1)
    models: list[str] = Field(min_length=1)
    mode: Literal["single", "collaborative", "independent"]
    prompt_strategy: Literal["analysis", "verification"]
    detected_ids: list[str] = Field(default_factory=list)
    execution_time: float = Field(ge=0)
    api_cost: float = Field(ge=0)
    logs: list[str] = Field(default_factory=list)


def init_integration_db():
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ai_integration_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id TEXT NOT NULL,
                models TEXT NOT NULL,
                mode TEXT NOT NULL,
                prompt_strategy TEXT NOT NULL,
                detected_ids TEXT NOT NULL,
                true_positive_ids TEXT NOT NULL,
                false_positive_ids TEXT NOT NULL,
                detection_rate REAL NOT NULL,
                precision_rate REAL NOT NULL,
                false_positive_count INTEGER NOT NULL,
                execution_time REAL NOT NULL,
                api_cost REAL NOT NULL,
                logs TEXT NOT NULL,
                is_sample INTEGER NOT NULL DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)


init_integration_db()


@router.get("/test-cases")
def get_test_cases():
    """Explain the simulated test-case IDs to other team members."""
    return {
        "is_sample": True,
        "test_cases": [
            {
                "target_id": target_id,
                "known_ids": sorted(known_ids),
                "note": "가상 정답 데이터입니다. 실제 취약점 검증 결과가 아닙니다.",
            }
            for target_id, known_ids in DEMO_GROUND_TRUTH.items()
        ],
    }


@router.post("/results", status_code=201)
def submit_ai_result(result: AIResult):
    """Accept model outputs as ID lists and score against synthetic ground truth."""
    if result.target_id not in DEMO_GROUND_TRUTH:
        raise HTTPException(status_code=400, detail="등록되지 않은 테스트 환경입니다.")
    if not set(result.models).issubset(ALLOWED_MODELS) or len(set(result.models)) != len(result.models):
        raise HTTPException(status_code=400, detail="모델 이름이 잘못됐거나 중복됐습니다.")
    if result.mode == "single" and len(result.models) != 1:
        raise HTTPException(status_code=400, detail="single 모드는 모델이 1개여야 합니다.")
    if result.mode == "collaborative" and len(result.models) < 2:
        raise HTTPException(status_code=400, detail="collaborative 모드는 모델이 2개 이상이어야 합니다.")

    known = DEMO_GROUND_TRUTH[result.target_id]
    detected = set(result.detected_ids)
    true_positives = sorted(detected & known)
    false_positives = sorted(detected - known)
    detection_rate = round(100 * len(true_positives) / len(known), 2)
    precision_rate = round(100 * len(true_positives) / len(detected), 2) if detected else 0.0

    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        cursor = conn.execute("""
            INSERT INTO ai_integration_runs (
                target_id, models, mode, prompt_strategy, detected_ids,
                true_positive_ids, false_positive_ids, detection_rate,
                precision_rate, false_positive_count, execution_time,
                api_cost, logs, is_sample
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            result.target_id,
            json.dumps(result.models, ensure_ascii=False),
            result.mode,
            result.prompt_strategy,
            json.dumps(sorted(detected), ensure_ascii=False),
            json.dumps(true_positives, ensure_ascii=False),
            json.dumps(false_positives, ensure_ascii=False),
            detection_rate,
            precision_rate,
            len(false_positives),
            result.execution_time,
            result.api_cost,
            json.dumps(result.logs, ensure_ascii=False),
        ))
        new_id = cursor.lastrowid

    return {
        "id": new_id,
        "message": "AI 결과가 저장되었습니다 (가상 정답 기준 평가).",
        "detection_rate": detection_rate,
        "precision_rate": precision_rate,
        "false_positive_count": len(false_positives),
        "is_sample": True,
    }


@router.get("/results")
def list_ai_results():
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM ai_integration_runs ORDER BY id DESC LIMIT 200"
        ).fetchall()
    runs = []
    for row in rows:
        item = dict(row)
        for name in ("models", "detected_ids", "true_positive_ids", "false_positive_ids", "logs"):
            item[name] = json.loads(item[name])
        item["is_sample"] = bool(item["is_sample"])
        runs.append(item)
    return {"runs": runs, "is_sample": True}