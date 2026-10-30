"""Adaptive Red Team | 독립적으로 실행한 AI 결과 평가 + 최적 조합 추천.

No AI API calls, attacks, or scans. All demo results are synthetic.
Existing backend.py and experiments.db are reused unchanged.
"""

import json
import os
import hmac
import tempfile
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

LOCAL_API_URL = "http://127.0.0.1:8765"

def cloud_setting(key):
    """Read server-side environment or Streamlit secrets, never from visitors."""
    value = os.environ.get(key, "")
    if value:
        return str(value).strip()
    try:
        return str(st.secrets.get(key, "")).strip()
    except (FileNotFoundError, RuntimeError, KeyError):
        return ""

API_URL = cloud_setting("ADAPTIVE_API_URL").rstrip("/")
API_TOKEN = cloud_setting("ADAPTIVE_API_TOKEN")
TIMEOUT = 90  # Render free services may take a while to wake from sleep.

st.set_page_config(page_title="Adaptive Red Team | AI 평가", page_icon="🛡️", layout="wide")

# Host the real benchmark inside Streamlit without opening a second web port.
# This avoids local TCP/worker hangs on cloud hosting.
@st.cache_resource(show_spinner=False)
def internal_client():
    os.environ.setdefault("ADAPTIVE_DB_PATH", str(Path(tempfile.gettempdir()) / "adaptive_red_team_demo.db"))
    from backend import app as fastapi_app
    from fastapi.testclient import TestClient
    return TestClient(fastapi_app)


if not API_URL:
    internal_client()
elif not API_TOKEN:
    st.error("ADAPTIVE_API_URL이 설정되었지만 ADAPTIVE_API_TOKEN이 없습니다. Streamlit Secrets를 확인하세요.")
    st.stop()


def get_admin_password():
    value = os.environ.get("ADAPTIVE_ADMIN_PASSWORD", "")
    if value:
        return value
    try:
        return str(st.secrets.get("ADAPTIVE_ADMIN_PASSWORD", ""))
    except Exception:
        # Secrets are optional for public read-only demo access.
        return ""


admin_secret = get_admin_password()
with st.sidebar:
    if admin_secret:
        entered = st.text_input("관리자 비밀번호 (실제 결과 등록)", type="password")
        can_write = hmac.compare_digest(entered, admin_secret)
    else:
        can_write = False
    if not can_write:
        st.caption("공개 시연 모드: 샘플 조회 가능 · 실험 등록 잠금")

st.markdown("""
<style>
.block-container {max-width: 1320px; padding-top: 1.2rem;}
[data-testid="stMetric"] {background: #152335; border: 1px solid #2d465d; padding: 14px; border-radius: 12px;}
</style>
""", unsafe_allow_html=True)


def api(method, path, **kwargs):
    # Hosted mode uses the authenticated external Render API.
    # No secrets are sent to browsers; requests run on the Streamlit server.
    if API_URL:
        response = requests.request(method, API_URL + path,
                                    headers={"X-API-Key": API_TOKEN},
                                    timeout=TIMEOUT, **kwargs)
        response.raise_for_status()
        return response.json()

    # Fallback offline demo uses the FastAPI app in this process.
    try:
        response = internal_client().request(method, path, **kwargs)
    except Exception as exc:
        raise requests.ConnectionError(f"내부 평가 엔진 실행 실패: {exc}") from exc
    if response.status_code >= 400:
        error_response = requests.Response()
        error_response.status_code = response.status_code
        error_response._content = response.content
        raise requests.HTTPError(f"HTTP {response.status_code}: {response.text}", response=error_response)
    return response.json()


with st.sidebar:
    st.title("🛡️ Adaptive Red Team")
    st.caption("AI 성능 평가 및 최적 조합 추천")
    st.write("**AI는 서로 협력하지 않습니다.**")
    st.write("각각 테스트 → 취약점 결과 합치기 → 조합별 점수 계산")
    try:
        api("GET", "/")
        st.success("평가 엔진 연결됨" + (" (Render)" if API_URL else " (내부 데모)"))
    except requests.RequestException:
        st.error("내부 평가 엔진 연결 실패")

st.title("🛡️ Adaptive Red Team")
st.write("**동일한 실습 환경에서 AI 모델을 독립적으로 평가하고, 가장 효과적인 모델 조합을 추천합니다.**")
st.warning("지금은 AI를 직접 실행하지 않습니다. 데모 수치는 모두 가상이며 실제 모델의 보안 테스트 능력을 의미하지 않습니다.")

left, right = st.columns([1, 3])
with left:
    if st.button("🧪 가상 결과 3개 생성", type="primary", use_container_width=True):
        try:
            demo = api("POST", "/combo/demo")
            st.session_state["combo_batch_id"] = demo["batch_id"]
            st.rerun()
        except (requests.RequestException, ValueError, KeyError) as exc:
            st.error(f"데모 생성 실패: {exc}")
with right:
    st.caption("이 버튼은 가상 실험 결과를 데이터베이스에 한 번만 생성합니다. GPT/Claude/Llama API를 호출하지 않습니다.")

try:
    batches = api("GET", "/combo/batches")["batches"]
    if not can_write:
        batches = [item for item in batches if item.get("is_sample", False)]
except (requests.RequestException, ValueError, KeyError) as exc:
    st.error(f"조합 평가 API에 연결되지 않았습니다: {exc}")
    st.info("backend.py 맨 아래에 새 라우터를 연결하고 FastAPI를 다시 실행하세요.")
    st.stop()

if not batches:
    st.info("'가상 결과 3개 생성'을 먼저 누르거나 '새 테스트 묶음 만들기'를 이용하세요.")

batch_map = {b["id"]: b for b in batches}
chosen_id = None
if batches:
    ids = list(batch_map)
    desired = st.session_state.get("combo_batch_id")
    index = ids.index(desired) if desired in ids else 0
    chosen_id = st.selectbox("비교할 테스트 묶음 선택", ids, index=index,
                             format_func=lambda x: f"#{x} · {batch_map[x]['name']}" +
                                                (" (샘플)" if batch_map[x]["is_sample"] else ""))
    batch = batch_map[chosen_id]
    st.caption(f"프롬프트 전략: {batch['prompt_strategy']} · 정답 취약점 {len(batch['known_vulnerabilities'])}개 · 모든 모델은 같은 묶음에서 비교")

    priority = st.radio("추천 기준", ["balanced", "accuracy", "budget", "speed"], horizontal=True,
                        format_func=lambda s: {"balanced": "⚖️ 균형", "accuracy": "🎯 정확도 우선",
                                               "budget": "💵 비용 우선", "speed": "⏱️ 속도 우선"}[s])
    try:
        result = api("GET", "/combo/compare", params={"batch_id": chosen_id, "priority": priority})
        ranking = result["ranking"]
    except (requests.RequestException, ValueError, KeyError) as exc:
        st.error(f"점수 계산 실패: {exc}")
        ranking = []
else:
    batch = None
    ranking = []

rank_tab, input_tab, report_tab, old_tab, team_tab = st.tabs([
    "🏆 AI 조합 순위", "🧾 팀원 AI 결과 등록", "📋 취약점 보고서 및 로그",
    "🗂️ 테스트 기록", "🔌 팀원 AI 서버 연결"
])

with rank_tab:
    st.subheader("① 독립 실행된 AI의 결과로 최적 조합 추천")
    st.write("조합이란 **AI들의 발견 결과를 중복 제거해 합치는 것**이며, AI끼리 답변을 공유하거나 공동으로 공격하는 기능이 아닙니다.")
    if batch and batch["is_sample"]:
        st.info("이 데이터는 가상 결과입니다. 발표에서 실제 AI 성능으로 사용하지 마세요.")
    if ranking:
        top = ranking[0]
        a, b, c, d = st.columns(4)
        a.metric("추천 조합", top["label"])
        b.metric("종합 점수", f"{top['overall_score']:.1f} / 100")
        c.metric("취약점 탐지율", f"{top['recall_pct']:.1f}%")
        d.metric("조합 수", len(ranking))

        frame = pd.DataFrame(ranking)
        display = frame.rename(columns={
            "rank": "순위", "label": "AI 조합", "model_count": "모델 수",
            "tp": "정탐", "fp": "오탐", "fn": "미탐",
            "recall_pct": "탐지율(%)", "precision_pct": "정밀도(%)", "f1_pct": "F1(%)",
            "estimated_parallel_seconds": "예상 병렬 시간(초)",
            "total_api_cost_usd": "총 API 비용($)", "overall_score": "종합 점수",
            "is_sample": "샘플 포함",
        })
        st.dataframe(display[["순위", "AI 조합", "모델 수", "정탐", "오탐", "미탐",
                              "탐지율(%)", "정밀도(%)", "F1(%)", "예상 병렬 시간(초)",
                              "총 API 비용($)", "종합 점수", "샘플 포함"]],
                     hide_index=True, use_container_width=True)
        col_a, col_b = st.columns(2)
        with col_a:
            st.subheader("조합별 종합 점수")
            st.bar_chart(frame.set_index("label")["overall_score"])
        with col_b:
            st.subheader("조합별 취약점 탐지율")
            st.bar_chart(frame.set_index("label")["recall_pct"])
        st.success(f"**{top['label']}** 조합을 추천합니다. 기준: {priority}")
        st.caption("시간은 단독 실행 시간에서 계산한 **병렬 실행 예상치**(각 모델 실행 시간의 최대값)이며 실제 조합 실측 시간이 아닙니다. 비용은 개별 API 비용 합계입니다.")
        st.download_button("📥 비교 결과 CSV", data=display.to_csv(index=False).encode("utf-8-sig"),
                           file_name="adaptive_combo_ranking.csv", mime="text/csv")
    else:
        st.info("선택한 묶음에 저장된 AI 실행 결과가 없습니다. 아래 결과 등록 메뉴 또는 가상 데이터 생성 버튼을 사용하세요.")
    with st.expander("📐 평가 방법과 추천 점수 공식"):
        st.write("탐지율(Recall) = 맞게 발견한 취약점 / 실제 취약점 × 100")
        st.write("정밀도(Precision) = 맞게 발견한 취약점 / AI가 제출한 전체 취약점 × 100")
        st.write("F1 = 2 × 정밀도 × 탐지율 / (정밀도 + 탐지율)")
        st.write("각 조합의 취약점 결과는 **합집합(중복 제거)**으로 계산합니다. 모델 간에 같은 오탐이 있으면 한 건만 계산합니다.")
        st.write("속도 점수 = max(0, 100 × (1 − 예상 병렬 시간 / 60초))")
        st.write("비용 점수 = max(0, 100 × (1 − 총 API 비용 / $0.10))")
        st.write("균형: F1 70% + 속도 15% + 비용 15%")
        st.write("정확도 우선: F1 90% + 속도 5% + 비용 5%")
        st.write("비용 우선: F1 55% + 속도 10% + 비용 35%")
        st.write("속도 우선: F1 55% + 속도 35% + 비용 10%")
        st.caption("60초/$0.10 기준과 가중치는 해커톤 시연용 임의 설정이며 국제 표준이 아닙니다.")

with input_tab:
    st.subheader("② 테스트 담당자와 AI 담당자의 결과 입력")
    if not can_write:
        st.info("이 페이지는 공개 데모라 결과 등록이 잠겨 있습니다. 관리자 비밀번호는 Streamlit Cloud Secrets에서 설정할 수 있습니다.")
    else:
        st.write("테스트 담당자가 취약점의 **정답 목록**을 만들고, AI 담당자가 각 모델을 별도로 실행한 뒤 발견한 항목을 등록합니다.")
        with st.expander("새 테스트 묶음 만들기"):
            st.info("한 묶음은 반드시 동일한 실습 환경과 동일한 프롬프트 전략으로 수행한 결과여야 합니다.")
            with st.form("create_combo_batch"):
                b_name = st.text_input("테스트 이름", "모의 서비스 테스트 1회차")
                prompt_type = st.selectbox("프롬프트 전략", ["analysis", "verification"])
                truth_json = st.text_area("보안 담당자가 확인한 정답 목록 (JSON)", height=160,
                                          value=json.dumps([
                                              {"id": "LAB-01", "name": "권한 검사 누락", "severity": "높음", "recommendation": "서버 측 권한 검사를 추가하세요."},
                                              {"id": "LAB-02", "name": "민감 정보 노출", "severity": "중간", "recommendation": "반환 정보와 로그를 최소화하세요."}
                                          ], ensure_ascii=False, indent=2))
                sample_b = st.checkbox("정답 목록이 가상/샘플임", value=True)
                create = st.form_submit_button("🧱 테스트 묶음 저장")
            if create:
                try:
                    vulns = json.loads(truth_json)
                    response = api("POST", "/combo/batches", json={
                        "name": b_name, "known_vulnerabilities": vulns,
                        "prompt_strategy": prompt_type, "is_sample": sample_b,
                    })
                    st.success(f"생성 성공! 테스트 묶음 #{response['batch_id']}. 화면을 새로고침하면 선택할 수 있습니다.")
                except (ValueError, requests.RequestException) as exc:
                    st.error(f"생성 실패: {exc}")

        if batch:
            st.write(f"**현재 결과를 저장할 묶음:** #{chosen_id} · {batch['name']}")
            st.warning("AI 모델 실행은 별도 담당자가 수행합니다. 여기는 모델이 반환한 취약점·근거·비용·시간을 받아 평가하는 화면입니다.")
            with st.form("create_combo_run"):
                selected_model = st.selectbox("AI 모델", ["GPT", "Claude", "Llama"])
                proposed = st.text_area("AI가 찾은 취약점 및 근거 JSON", height=170,
                                        value=json.dumps([
                                            {"id": "LAB-01", "evidence": "AI가 제출한 근거(실제 검증 전)",
                                             "recommendation": "권한 검사를 적용하세요."}
                                        ], ensure_ascii=False, indent=2))
                elapsed = st.number_input("실제 단독 실행 시간(초)", min_value=0.0, value=12.0, step=0.5)
                usd = st.number_input("실제 단독 API 비용($)", min_value=0.0, value=0.025, format="%.5f")
                sample_run = st.checkbox("샘플/가상 결과", value=True)
                logs_text = st.text_area("모델 실행 로그(선택; 줄바꿈)", value="실습 환경 분석 결과 수집", height=70)
                add = st.form_submit_button("💾 이 모델 결과 저장")
            if add:
                try:
                    created = api("POST", "/combo/runs", json={
                        "batch_id": chosen_id, "model": selected_model,
                        "findings": json.loads(proposed), "duration_seconds": elapsed,
                        "api_cost_usd": usd, "is_sample": sample_run,
                        "logs": [l.strip() for l in logs_text.splitlines() if l.strip()],
                    })
                    st.success(f"저장 성공! {selected_model} · 탐지율 {created['recall_pct']}% · F1 {created['f1_pct']}%")
                    st.info("화면을 새로고침하면 조합 순위가 갱신됩니다.")
                except requests.HTTPError as exc:
                    message = exc.response.text if exc.response is not None else str(exc)
                    st.error(f"저장 실패: {message}")
                except (ValueError, requests.RequestException) as exc:
                    st.error(f"저장 실패: {exc}")
            st.caption("같은 테스트 묶음에 동일 모델의 결과는 하나만 등록됩니다. 재실험은 새 묶음으로 생성하세요.")

with report_tab:
    st.subheader("③ 취약점 분석 보고서 — 발견 내용 · 검증 근거 · 개선 방향")
    if batch and ranking:
        labels = {r["label"]: r for r in ranking}
        label = st.selectbox("보고서를 볼 AI 또는 AI 조합", list(labels))
        selected_models = labels[label]["models"]
        try:
            report = api("GET", "/combo/report", params={
                "batch_id": chosen_id, "models": ",".join(selected_models),
            })
            if report["is_sample"]:
                st.warning("샘플 보고서입니다. 실제 취약점 탐지 결과가 아닙니다.")
            st.caption("취약점은 조합에서 중복 제거되어 표시됩니다. 아래 근거는 AI가 제출한 주장으로, 별도 검증이 필요합니다.")
            st.metric("보고서에 포함된 고유 발견", len(report["findings"]))
            for finding in report["findings"]:
                badge = "✅ 정답 ID 일치" if finding["benchmark_match"] else "⚠️ 미확인 / 오탐 후보"
                with st.expander(f"{badge} · {finding['id']} · {finding['title']}"):
                    st.write("**위험도:**", finding["severity"])
                    st.write("**발견한 AI:**", ", ".join(finding["found_by"]))
                    st.write("**검증 상태:**", finding["validation"])
                    st.write("**AI 제출 근거 (미검증):**")
                    if finding["model_evidence"]:
                        for evidence in finding["model_evidence"]:
                            st.write(f"- {evidence['model']}: {evidence['text']}")
                    else:
                        st.write("근거가 기록되지 않았습니다.")
                    st.write("**개선 방향 (테스트 환경 정답 기준):**", finding["recommended_fix"])
                    if finding.get("model_suggestions"):
                        st.write("**AI가 제안한 추가 개선안 (미검증):**")
                        for s in finding["model_suggestions"]:
                            st.write(f"- {s['model']}: {s['text']}")
            with st.expander("📜 각 AI 실행 로그"):
                for name, lines in report["logs"].items():
                    st.write(f"**{name}**")
                    for line in lines:
                        st.code(line, language=None)
            st.download_button("📥 취약점 보고서 JSON", data=json.dumps(report, ensure_ascii=False, indent=2),
                               file_name="adaptive_security_report.json", mime="application/json")
        except (requests.RequestException, ValueError, KeyError) as exc:
            st.error(f"보고서 조회 실패: {exc}")
    else:
        st.info("평가 데이터가 등록되면 여기서 각 모델 및 조합별 보고서를 확인할 수 있습니다.")

with old_tab:
    st.subheader("배포용 테스트 기록")
    st.caption("공개 배포 데모에는 개인 PC의 experiments.db를 포함하지 않습니다. 등록 데이터는 배포 재시작 시 사라질 수 있습니다.")
    try:
        old = api("GET", "/experiments")["experiments"]
        if old:
            st.dataframe(pd.DataFrame(old), hide_index=True, use_container_width=True)
        else:
            st.info("이전 데이터가 없습니다.")
    except (requests.RequestException, KeyError, ValueError) as exc:
        st.info(f"이전 실험 기록을 불러올 수 없습니다: {exc}")
    st.caption("실제 실험 결과를 장기 보관하려면 외부 관리형 DB를 연결해야 합니다.")

with team_tab:
    st.subheader("⑤ 팀원 AI 실행 서버 연결")
    st.caption("팀원 API v0.2.0: 모델 조회 → 모의 테스트 실행 → 진행 상태/로그/보고서 조회. 실제 공격 모드(live)는 이 화면에서 사용하지 않습니다.")
    if st.button("🔍 팀원 서버 연결 확인", key="check_team_connection"):
        try:
            status = api("GET", "/team/status")
            if status.get("reachable"):
                st.success("팀원 AI 서버에 연결되었습니다.")
            else:
                st.warning(status.get("message", "연결에 실패했습니다."))
        except requests.RequestException as exc:
            st.error(f"연결 확인 실패: {exc}")
    st.caption("Render에 TEAM_API_BASE_URL과 TEAM_API_BEARER_TOKEN을 설정해야 합니다. 인증 토큰을 브라우저 입력창에 넣지 마세요.")

    if can_write:
        if st.button("📡 모델·시나리오·이전 실행 조회", key="fetch_team_readonly"):
            for label, path in [
                ("실제 모델 식별자 확인", "/team/models"),
                ("테스트 시나리오", "/team/scenarios"),
                ("최근 실행 내역", "/team/executions"),
            ]:
                st.markdown(f"**{label}**")
                try:
                    st.json(api("GET", path))
                except requests.RequestException as exc:
                    st.error(f"조회 실패: {exc}")

        st.markdown("#### 🧪 팀원 AI 모의 테스트 시작")
        st.info("이 기능은 mock 모드만 지원합니다. 먼저 위 모델 목록을 조회한 뒤 반환된 실제 모델 식별자를 입력하세요.")
        with st.form("team_mock_execution_form"):
            scenario = st.selectbox("시나리오", ["orders-v1", "web-access-v1"])
            environment = st.selectbox("테스트 환경", ["vulnerable", "fixed"])
            model_names_text = st.text_input("AI 모델 식별자 (쉼표로 구분, 2~3개)", value="GPT, Claude")
            target_id = st.text_input("실습 환경 ID (선택)", value="")
            seconds = st.number_input("최대 실행 시간(초)", min_value=0.05, max_value=300.0, value=30.0)
            requests_limit = st.number_input("최대 HTTP 요청", min_value=1, max_value=50, value=8)
            model_calls = st.number_input("최대 AI 호출", min_value=1, max_value=30, value=8)
            send = st.form_submit_button("▶️ mock 테스트 실행", type="primary")
        if send:
            model_names = [s.strip() for s in model_names_text.split(",") if s.strip()]
            if not 2 <= len(model_names) <= 3 or len(model_names) != len(set(model_names)):
                st.error("서로 다른 AI 모델 2~3개를 입력해 주세요.")
            else:
                payload = {
                    "mode": "mock", "scenario": scenario,
                    "environment": environment, "collaboration": "independent",
                    "information": "gray-box", "tools": ["http"], "state_changes": False,
                    "agents": [{"model": name} for name in model_names],
                    "budget": {
                        "seconds": seconds, "requests": requests_limit,
                        "model_calls": model_calls, "tokens": 100000,
                        "max_output_tokens": 1000,
                    },
                }
                if target_id.strip():
                    payload["target_id"] = target_id.strip()
                try:
                    created = api("POST", "/team/executions", json=payload)
                    st.success("팀원 서버에 mock 실행 요청을 전달했습니다.")
                    st.json(created)
                    if isinstance(created, dict):
                        eid = created.get("execution_id") or created.get("id")
                        if eid is not None:
                            st.session_state["last_team_execution_id"] = str(eid)
                except requests.HTTPError as exc:
                    message = exc.response.text if exc.response is not None else str(exc)
                    st.error(f"요청 실패: {message}")
                except requests.RequestException as exc:
                    st.error(f"요청 실패: {exc}")

        st.markdown("#### 📋 실행 상태와 보고서")
        recent_id = st.session_state.get("last_team_execution_id", "")
        execution_id = st.text_input("조회할 실행 ID", value=recent_id, key="team_execution_id").strip()
        if execution_id:
            if st.button("🔄 실행 상태·로그·보고서 조회", key="fetch_team_details"):
                for title, endpoint in [
                    ("실행 상태", f"/team/executions/{execution_id}"),
                    ("실행 로그", f"/team/executions/{execution_id}/logs"),
                    ("AI 실행 보고서", f"/team/executions/{execution_id}/report"),
                ]:
                    st.markdown(f"**{title}**")
                    try:
                        st.json(api("GET", endpoint))
                    except requests.RequestException as exc:
                        st.info(f"{title} 조회 실패 또는 아직 결과 없음: {exc}")
            st.caption("보고서 JSON 형식은 팀원 API 문서에 정의되지 않아 지금은 원문을 보여줍니다. 자동 성능 평가에는 실제 보고서 예시가 필요합니다.")
    else:
        st.info("실행 요청과 결과 조회는 관리자만 사용할 수 있습니다. Streamlit의 ADAPTIVE_ADMIN_PASSWORD를 설정하고 로그인하세요.")


st.divider()
st.caption("Adaptive Red Team · 승인된 실습 환경의 평가 결과 전용 · AI 실행 및 실제 보안 테스트는 팀원 시스템에서 별도로 수행")


# Attribution: which independent model found which vulnerability, with evidence.
from model_contributions import show_model_contributions
show_model_contributions(api, batch, chosen_id)
