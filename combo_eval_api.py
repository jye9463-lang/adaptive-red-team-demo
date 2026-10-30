"""Adaptive Red Team: independent-model security benchmark and combination evaluation.

SAFETY/INTEGRITY: No AI calls, target access, scans, or exploit execution.
Combinations mean merging findings from separately run models, NOT AI cooperation.
Ground truth must come from the authorized lab's evaluator, not from model output.
Unauthenticated API: expose on localhost only until auth is added.
"""

import itertools
import os
import json
import sqlite3
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/combo", tags=["AI 성능 평가 · 조합 추천"])
DB_PATH = Path(os.environ.get("ADAPTIVE_DB_PATH", str(Path(__file__).with_name("experiments.db"))))
MODELS = ("GPT", "Claude", "Llama")
TIME_LIMIT = 60.0  # 설명 가능한 해커톤 데모 기준. 표준 아님.
COST_LIMIT = 0.10   # USD. 표준 아님.
WEIGHTS = {
    "balanced": (0.70, 0.15, 0.15),
    "accuracy": (0.90, 0.05, 0.05),
    "budget": (0.55, 0.10, 0.35),
    "speed": (0.55, 0.35, 0.10),
}


class Vulnerability(BaseModel):
    id: str = Field(min_length=1, max_length=60)
    name: str = Field(min_length=1, max_length=150)
    severity: Literal["낮음", "중간", "높음", "치명적"] = "중간"
    recommendation: str = Field(default="", max_length=3000)


class BatchIn(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    known_vulnerabilities: list[Vulnerability] = Field(min_length=1, max_length=100)
    prompt_strategy: Literal["analysis", "verification"] = "analysis"
    is_sample: bool = True


class Finding(BaseModel):
    id: str = Field(min_length=1, max_length=60)
    evidence: str = Field(default="", max_length=4000)
    recommendation: str = Field(default="", max_length=4000)


class ModelRunIn(BaseModel):
    batch_id: int = Field(gt=0)
    model: Literal["GPT", "Claude", "Llama"]
    findings: list[Finding] = Field(default_factory=list, max_length=200)
    duration_seconds: float = Field(ge=0)
    api_cost_usd: float = Field(ge=0)
    is_sample: bool = True
    logs: list[str] = Field(default_factory=list, max_length=100)


def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def initialize():
    con = db()
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS combo_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                demo_key TEXT UNIQUE,
                name TEXT NOT NULL,
                prompt_strategy TEXT NOT NULL,
                known_json TEXT NOT NULL,
                is_sample INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS combo_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id INTEGER NOT NULL,
                model TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                duration_seconds REAL NOT NULL,
                api_cost_usd REAL NOT NULL,
                logs_json TEXT NOT NULL,
                is_sample INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(batch_id, model),
                FOREIGN KEY(batch_id) REFERENCES combo_batches(id)
            )
        """)
        con.commit()
    finally:
        con.close()


initialize()


def canonical_id(v):
    return str(v).strip().upper()


def clean_truth(vulns):
    seen = set()
    result = []
    for item in vulns:
        row = item.model_dump() if hasattr(item, "model_dump") else dict(item)
        row["id"] = canonical_id(row["id"])
        if not row["id"] or row["id"] in seen:
            raise HTTPException(422, "정답 취약점 ID는 비어 있거나 중복되면 안 됩니다.")
        seen.add(row["id"])
        result.append(row)
    return result


def clean_findings(findings):
    # 동일한 ID를 여러 번 찾아도 한 번만 계산합니다.
    ids = set()
    result = []
    for item in findings:
        row = item.model_dump() if hasattr(item, "model_dump") else dict(item)
        row["id"] = canonical_id(row["id"])
        if row["id"] and row["id"] not in ids:
            ids.add(row["id"])
            result.append(row)
    return result


def load_batch(con, batch_id):
    batch = con.execute("SELECT * FROM combo_batches WHERE id=?", (batch_id,)).fetchone()
    if batch is None:
        raise HTTPException(404, "등록되지 않은 테스트 묶음입니다.")
    data = dict(batch)
    data["known_vulnerabilities"] = json.loads(data.pop("known_json"))
    data["is_sample"] = bool(data["is_sample"])
    return data


def load_runs(con, batch_id):
    rows = con.execute(
        "SELECT * FROM combo_runs WHERE batch_id=? ORDER BY id", (batch_id,)
    ).fetchall()
    output = []
    for r in rows:
        item = dict(r)
        item["findings"] = json.loads(item.pop("findings_json"))
        item["logs"] = json.loads(item.pop("logs_json"))
        item["is_sample"] = bool(item["is_sample"])
        output.append(item)
    return output


def scores(truth_ids, submitted_ids, seconds, usd, priority):
    t = set(truth_ids)
    s = set(submitted_ids)
    tp = sorted(t & s)
    fp = sorted(s - t)
    fn = sorted(t - s)
    precision = len(tp) / len(s) if s else 0.0
    recall = len(tp) / len(t) if t else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    speed = 100 * max(0.0, 1.0 - seconds / TIME_LIMIT)
    budget = 100 * max(0.0, 1.0 - usd / COST_LIMIT)
    wf1, wtime, wcost = WEIGHTS[priority]
    overall = wf1 * 100 * f1 + wtime * speed + wcost * budget
    return {
        "tp_ids": tp, "fp_ids": fp, "fn_ids": fn,
        "tp": len(tp), "fp": len(fp), "fn": len(fn),
        "recall_pct": round(recall * 100, 2),
        "precision_pct": round(precision * 100, 2),
        "f1_pct": round(f1 * 100, 2),
        "overall_score": round(overall, 2),
    }


def combo_report(batch, runs, selected):
    reference = {r["id"]: r for r in batch["known_vulnerabilities"]}
    by_id = {}
    for run in runs:
        if run["model"] not in selected:
            continue
        for f in run["findings"]:
            entry = by_id.setdefault(f["id"], {
                "id": f["id"], "found_by": [], "model_evidence": [],
            })
            entry["found_by"].append(run["model"])
            if f["evidence"]:
                entry["model_evidence"].append({
                    "model": run["model"], "text": f["evidence"],
                    "label": "AI가 제출한 근거 · 별도 확인 필요",
                })
            if f["recommendation"]:
                entry.setdefault("model_suggestions", []).append({
                    "model": run["model"], "text": f["recommendation"],
                })
    result = []
    for vid in sorted(by_id):
        entry = by_id[vid]
        truth = reference.get(vid)
        if truth:
            entry.update({
                "title": truth["name"], "severity": truth["severity"],
                "benchmark_match": True,
                "validation": "정답 목록에 있음 (실제 검증은 테스트 담당 확인 필요)",
                "recommended_fix": truth["recommendation"],
            })
        else:
            entry.update({
                "title": "정답 목록 밖에서 제시한 취약점",
                "severity": "미확인", "benchmark_match": False,
                "validation": "정답 목록에 없음 · 오탐 후보, 추가 검토 필요",
                "recommended_fix": "먼저 발견 주장과 증거를 검토하세요.",
            })
        result.append(entry)
    return result


@router.post("/batches", status_code=201)
def create_batch(payload: BatchIn):
    truth = clean_truth(payload.known_vulnerabilities)
    con = db()
    try:
        cur = con.execute("""
            INSERT INTO combo_batches (name, prompt_strategy, known_json, is_sample)
            VALUES (?,?,?,?)
        """, (payload.name, payload.prompt_strategy,
              json.dumps(truth, ensure_ascii=False), int(payload.is_sample)))
        con.commit()
        return {"batch_id": cur.lastrowid, "message": "테스트 묶음 생성", "is_sample": payload.is_sample}
    finally:
        con.close()


@router.get("/batches")
def list_batches():
    con = db()
    try:
        rows = con.execute("SELECT id FROM combo_batches ORDER BY id DESC LIMIT 100").fetchall()
        return {"batches": [load_batch(con, row["id"]) for row in rows]}
    finally:
        con.close()


@router.post("/runs", status_code=201)
def create_run(payload: ModelRunIn):
    con = db()
    try:
        batch = load_batch(con, payload.batch_id)
        findings = clean_findings(payload.findings)
        is_sample = bool(batch["is_sample"]) or payload.is_sample
        try:
            cur = con.execute("""
                INSERT INTO combo_runs
                (batch_id, model, findings_json, duration_seconds, api_cost_usd, logs_json, is_sample)
                VALUES (?,?,?,?,?,?,?)
            """, (payload.batch_id, payload.model,
                  json.dumps(findings, ensure_ascii=False),
                  payload.duration_seconds, payload.api_cost_usd,
                  json.dumps(payload.logs, ensure_ascii=False), int(is_sample)))
            con.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "이 테스트 묶음에 해당 모델의 결과가 이미 있습니다. 새 묶음을 만드세요.")
        truth_ids = [v["id"] for v in batch["known_vulnerabilities"]]
        report = scores(truth_ids, [f["id"] for f in findings], payload.duration_seconds,
                        payload.api_cost_usd, "balanced")
        return {"run_id": cur.lastrowid, "model": payload.model,
                "is_sample": is_sample, **report}
    finally:
        con.close()


@router.get("/runs")
def get_runs(batch_id: int = Query(gt=0)):
    con = db()
    try:
        load_batch(con, batch_id)
        return {"runs": load_runs(con, batch_id)}
    finally:
        con.close()


@router.get("/compare")
def compare(batch_id: int = Query(gt=0),
            priority: Literal["balanced", "accuracy", "budget", "speed"] = "balanced"):
    con = db()
    try:
        batch = load_batch(con, batch_id)
        runs = load_runs(con, batch_id)
    finally:
        con.close()
    by_model = {r["model"]: r for r in runs}
    candidates = []
    known = [v["id"] for v in batch["known_vulnerabilities"]]
    available = [m for m in MODELS if m in by_model]
    for size in range(1, len(available) + 1):
        for names in itertools.combinations(available, size):
            chosen = [by_model[n] for n in names]
            found_ids = {f["id"] for run in chosen for f in run["findings"]}
            total_cost = sum(r["api_cost_usd"] for r in chosen)
            # 시간은 따로 실행된 단일 모델 실행 시간에서 추정한 값; 실측 조합 시간 아님.
            est_parallel = max(r["duration_seconds"] for r in chosen)
            est_sequential = sum(r["duration_seconds"] for r in chosen)
            metric = scores(known, found_ids, est_parallel, total_cost, priority)
            candidates.append({
                "models": list(names), "label": " + ".join(names),
                "model_count": len(names), "found_ids": sorted(found_ids),
                "estimated_parallel_seconds": round(est_parallel, 3),
                "estimated_sequential_seconds": round(est_sequential, 3),
                "total_api_cost_usd": round(total_cost, 6),
                "is_sample": batch["is_sample"] or any(r["is_sample"] for r in chosen),
                **metric,
            })
    candidates.sort(key=lambda x: (-x["overall_score"], -x["f1_pct"],
                                   x["total_api_cost_usd"], x["label"]))
    for index, row in enumerate(candidates, 1):
        row["rank"] = index
    return {
        "batch": batch, "priority": priority,
        "weights": dict(zip(("f1", "speed", "cost"), WEIGHTS[priority])),
        "ranking": candidates,
        "recommendation": candidates[0] if candidates else None,
        "time_note": "조합 소요 시간은 모든 AI가 동시에 실행된다는 가정의 최대값(예상치)입니다. 실제 병렬 실행 측정값이 아닙니다.",
        "validation_note": "미등록 취약점 ID는 오탐 후보로 계산합니다. 정답 목록이 완전하고 AI 결과가 검증된 조건에서만 해석하세요.",
    }


@router.get("/report")
def report(batch_id: int = Query(gt=0), models: str = Query(min_length=1)):
    selected = [v.strip() for v in models.split(",") if v.strip()]
    if not selected or len(selected) != len(set(selected)) or any(m not in MODELS for m in selected):
        raise HTTPException(422, "모델 이름은 GPT,Claude,Llama 중에서 중복 없이 선택하세요.")
    con = db()
    try:
        batch = load_batch(con, batch_id)
        runs = load_runs(con, batch_id)
    finally:
        con.close()
    existing = {r["model"] for r in runs}
    if not set(selected).issubset(existing):
        raise HTTPException(404, "선택한 AI의 실행 결과가 없습니다.")
    return {
        "batch_id": batch_id, "models": selected,
        "is_sample": batch["is_sample"] or any(r["is_sample"] for r in runs if r["model"] in selected),
        "findings": combo_report(batch, runs, selected),
        "logs": {r["model"]: r["logs"] for r in runs if r["model"] in selected},
        "notice": "검증 근거는 AI의 제출 내용입니다. 모의 서비스의 원본 로그 등과 대조해 확인하세요.",
    }


@router.post("/demo")
def seed_demo():
    """동일한 가상 환경을 3개 AI가 독립 평가한 것으로 가정한 데이터. AI 호출 없음."""
    con = db()
    try:
        row = con.execute("SELECT id FROM combo_batches WHERE demo_key=?", ("combo-demo-v1",)).fetchone()
        if row is None:
            truth = [
                {"id":"LAB-01", "name":"인증 확인 누락 (가상)", "severity":"높음",
                 "recommendation":"인증이 필요한 API에 서버 측 인증 검사를 적용하세요."},
                {"id":"LAB-02", "name":"권한 범위 과다 (가상)", "severity":"높음",
                 "recommendation":"사용자/역할별 최소 권한을 적용하세요."},
                {"id":"LAB-03", "name":"민감 정보 노출 (가상)", "severity":"중간",
                 "recommendation":"응답 필드와 로그의 민감 정보를 최소화하세요."},
                {"id":"LAB-04", "name":"검증되지 않은 입력 (가상)", "severity":"중간",
                 "recommendation":"서버 측 입력 검증을 추가하세요."},
                {"id":"LAB-05", "name":"비밀키 관리 미흡 (가상)", "severity":"높음",
                 "recommendation":"비밀키를 환경변수/비밀관리시스템에 보관하고 교체하세요."},
            ]
            cur = con.execute("""
                INSERT INTO combo_batches (demo_key, name, prompt_strategy, known_json, is_sample)
                VALUES (?,?,?,?,1)
            """, ("combo-demo-v1", "가상 모의 서비스 · 정답 취약점 5개", "analysis",
                  json.dumps(truth, ensure_ascii=False)))
            bid = cur.lastrowid
        else:
            bid = row["id"]
        if not con.execute("SELECT 1 FROM combo_runs WHERE batch_id=? LIMIT 1", (bid,)).fetchone():
            demo = [
                ("GPT", ["LAB-01", "LAB-02", "LAB-03", "EXTRA-01"], 13.0, 0.030),
                ("Claude", ["LAB-02", "LAB-04", "LAB-05", "EXTRA-02"], 11.0, 0.025),
                ("Llama", ["LAB-01", "LAB-04", "EXTRA-03"], 7.0, 0.007),
            ]
            for model, ids, sec, usd in demo:
                findings = [{"id":v, "evidence":f"데모: {model}의 가상 확인 내용 (실제 검증 아님)",
                             "recommendation":"데모용 기록입니다."} for v in ids]
                con.execute("""
                    INSERT INTO combo_runs
                    (batch_id, model, findings_json, duration_seconds, api_cost_usd, logs_json, is_sample)
                    VALUES (?,?,?,?,?,?,1)
                """, (bid, model, json.dumps(findings, ensure_ascii=False), sec, usd,
                      json.dumps([f"데모: {model} 결과 입력", "실제 AI 모델 호출 없음"], ensure_ascii=False)))
        con.commit()
        return {"batch_id": bid, "is_sample": True,
                "message": "가상 데이터 준비 완료 (실제 AI 실행은 하지 않았습니다)."}
    finally:
        con.close()
