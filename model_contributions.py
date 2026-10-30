"""Adaptive Red Team - independent AI finding attribution dashboard.

This is a read-only Streamlit addon; it does not execute any AI or security tests.
Uses existing GET /combo/runs?batch_id=... endpoint and the known ground truth
stored in /combo/batches. Works with the existing FastAPI backend.
"""

from collections import defaultdict

import pandas as pd
import requests
import streamlit as st


MODEL_NAMES = ("GPT", "Claude", "Llama")


def build_contribution_tables(batch: dict, runs: list[dict]):
    """Build an attribution matrix and per-model summaries without changing DB.

    Returns (matrix: pd.DataFrame, summary: pd.DataFrame, evidence_by_id: dict).
    Model discoveries are counted once per vulnerability ID within a run.
    Unknown IDs are *candidates* for false positives, not proof of error.
    """
    truth = {str(v["id"]).strip().upper(): v for v in batch["known_vulnerabilities"]}
    submitted = defaultdict(dict)
    run_by_model = {run["model"]: run for run in runs}
    for run in runs:
        model = run["model"]
        for finding in run.get("findings", []):
            fid = str(finding["id"]).strip().upper()
            if fid and model not in submitted[fid]:
                submitted[fid][model] = finding

    all_ids = sorted(set(truth) | set(submitted))
    matrix_rows = []
    for fid in all_ids:
        models = [m for m in MODEL_NAMES if m in submitted.get(fid, {})]
        known = fid in truth
        if not models:
            contribution = "미탐지"
        elif not known:
            contribution = "추가 확인 필요"
        elif len(models) == 1:
            contribution = f"{models[0]} 단독 발견"
        else:
            contribution = "여러 모델이 중복 발견"

        matrix_rows.append({
            "취약점 ID": fid,
            "발견 항목": truth[fid]["name"] if known else "정답 목록 외 제보 (미확인)",
            "판정": "정답 목록과 일치" if known else "오탐 후보 / 추가 검증",
            **{m: ("미실행" if m not in run_by_model else ("✅ 발견" if m in models else "—")) for m in MODEL_NAMES},
            "기여 형태": contribution,
        })

    summaries = []
    for model in MODEL_NAMES:
        run = run_by_model.get(model)
        if not run:
            continue
        discovered = {fid for fid, by in submitted.items() if model in by}
        correct = discovered & truth.keys()
        unique = {fid for fid in correct if len(submitted[fid]) == 1}
        shared = correct - unique
        unresolved = discovered - truth.keys()
        summaries.append({
            "AI 모델": model,
            "정답 일치": len(correct),
            "단독 기여": len(unique),
            "공동 발견": len(shared),
            "오탐 후보": len(unresolved),
            "놓친 정답": len(truth) - len(correct),
            "실행 시간(초)": round(run["duration_seconds"], 3),
            "API 비용($)": round(run["api_cost_usd"], 6),
            "샘플 여부": "샘플" if run["is_sample"] else "실측 표기(검증 필요)",
        })

    return pd.DataFrame(matrix_rows), pd.DataFrame(summaries), submitted


def show_model_contributions(api, batch: dict | None, batch_id: int | None):
    """Display contribution details below the original Streamlit dashboard.

    `api` should be the helper `api(method, path, **kwargs)` already in app.py.
    """
    st.divider()
    st.header("🧩 AI별 발견 항목 및 기여도")
    st.caption("모든 AI는 독립적으로 분석합니다. 아래 표는 AI별로 어떤 취약점을 제보했는지와 중복 발견을 구분합니다.")

    if not batch or batch_id is None:
        st.info("먼저 테스트 묶음을 선택하거나 가상 결과를 생성하세요.")
        return

    try:
        payload = api("GET", "/combo/runs", params={"batch_id": batch_id})
        runs = payload["runs"]
    except (requests.RequestException, KeyError, ValueError) as exc:
        st.error(f"AI별 결과를 불러오지 못했습니다: {exc}")
        return

    if not runs:
        st.info("이 테스트 묶음에는 아직 AI별 분석 결과가 없습니다.")
        return

    if batch.get("is_sample") or any(run.get("is_sample") for run in runs):
        st.warning("샘플 데이터가 포함되어 있습니다. 실제 AI의 보안 테스트 성능이나 공헌도를 뜻하지 않습니다.")

    matrix, summary, submitted = build_contribution_tables(batch, runs)
    truth = {str(v["id"]).strip().upper(): v for v in batch["known_vulnerabilities"]}
    registered = {r["model"] for r in runs}

    st.subheader("1. 어느 AI가 어떤 취약점을 발견했나요?")
    st.dataframe(matrix, hide_index=True, use_container_width=True)
    st.caption("✅ 발견 = 해당 AI가 그 ID를 제보함. 정답 목록 일치 여부와 원본 근거 검증은 별개입니다. — = 실행했지만 해당 AI가 제보하지 않음. 미실행 = 실행 결과가 등록되지 않음.")

    st.subheader("2. AI별 기여 비교")
    st.dataframe(summary, hide_index=True, use_container_width=True)
    st.caption("단독 기여는 다른 AI가 찾지 못한 *정답 목록의 취약점*을 해당 AI만 찾은 건수입니다. 같은 취약점은 조합 성능에서 한 번만 계산합니다.")

    st.subheader("3. 취약점별 AI 제출 근거와 개선 방향")
    only_found = matrix[matrix["기여 형태"] != "미탐지"]
    if only_found.empty:
        st.info("AI가 보고한 취약점이 없습니다.")
    for _, row in only_found.iterrows():
        fid = row["취약점 ID"]
        by = submitted[fid]
        with st.expander(f"{fid} · {row['발견 항목']} · 발견 AI: {', '.join(by)}"):
            st.write("**정답 목록 판정:**", row["판정"])
            if fid in truth:
                st.write("**정답 기준 개선 방향:**", truth[fid].get("recommendation", "등록되지 않음"))
            for model in MODEL_NAMES:
                finding = by.get(model)
                if finding is not None:
                    st.markdown(f"**{model}가 제출한 내용**")
                    st.write("검증 근거(미검증):", finding.get("evidence") or "기록 없음")
                    st.write("AI 제안 개선안(미검증):", finding.get("recommendation") or "기록 없음")

    with st.expander("📜 각 AI의 개별 실행 로그"):
        for model in MODEL_NAMES:
            if model not in registered:
                continue
            st.write(f"**{model}**")
            run = next(r for r in runs if r["model"] == model)
            if run.get("logs"):
                for line in run["logs"]:
                    st.text(line)
            else:
                st.caption("등록된 로그 없음")

    st.download_button(
        "📥 AI별 기여도 CSV 다운로드",
        matrix.to_csv(index=False).encode("utf-8-sig"),
        file_name=f"ai_contributions_batch_{batch_id}.csv",
        mime="text/csv",
        key=f"contributions_{batch_id}",
    )
