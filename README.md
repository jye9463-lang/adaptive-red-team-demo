# Adaptive Red Team — 해커톤 배포용 (Streamlit Community Cloud)

이 패키지는 **AI들이 별도로 제출한 모의해킹 결과**를 평가하고, 단독 모델과 **독립 실행 결과의 조합**을 비교하는 **배포용 데모**입니다. AI끼리 협력하지 않으며, 실제 AI 모델 호출·공격·스캔을 수행하지 않습니다.

## 기능

- GPT / Claude / Llama의 독립 평가 결과 저장(관리자 전용)
- 정답 목록 기준 탐지율·정밀도·F1 점수·시간·비용 비교
- 단독 모델 3종 + 조합 4종 평가 및 목적별 추천
- 어떤 모델이 어떤 취약점 ID를 제보했는지, 중복/단독 기여도 표시
- 모델별 검증 근거(미확인 AI 주장), 개선 방향, 로그, CSV/JSON 내려받기
- 앱 실행 시 **가상 데이터 자동 로드**. 공개 화면은 샘플 데이터만 표시

## 처음부터 웹에 배포하기 (초보자용)

1. 이 ZIP의 **내용물을 풀어서** 새 폴더에 보관하세요. 현재 작업 중인 `Adaptive-Red-Team` 폴더는 덮어쓰지 마세요.
2. **GitHub** 로그인 → **New repository** → 이름 `adaptive-red-team-demo` → 저장소 생성. 코드는 공개해도 되는 데모만 포함되어 있습니다.
3. 새 저장소에서 **Add file → Upload files** → 이 폴더의 파일과 `.streamlit` 폴더를 올리고 **Commit changes**를 누르세요. `requirements.txt`, `app.py`, `backend.py`, `combo_eval_api.py`, `model_contributions.py`가 최상단에 있어야 합니다. `experiments.db`, `.env`, 실제 고객 데이터 및 API 키는 올리지 마세요.
4. [Streamlit Community Cloud](https://share.streamlit.io/) 에 GitHub로 로그인 → **Create app** → 저장소 `adaptive-red-team-demo`, branch `main`, main file `app.py` → **Deploy**.
5. 앱 주소 `https://<선택한-이름>.streamlit.app`가 열리면 **AI 조합 순위**와 **AI별 발견 항목 및 기여도**를 확인하세요. **가상 결과 3개 생성** 버튼은 재실행해도 이미 생성된 데모를 재사용합니다.

**필수 환경 변수는 없습니다.** 앱 내부에서 루프백 주소 `127.0.0.1:8765`로 FastAPI를 자동 실행하므로 **배포 서버를 따로 만들 필요가 없습니다.**

## 실험 결과를 직접 등록하려면

Streamlit Community Cloud 앱의 **Settings → Secrets**에서 아래처럼 입력합니다.

```toml
ADAPTIVE_ADMIN_PASSWORD = "충분히-길고-랜덤한-비밀번호"
```

로그아웃한 방문객에게는 **샘플 데이터만 보여집니다**. 관리자만 왼쪽 사이드바에 비밀번호를 입력해 **팀원 AI 결과 등록** 메뉴를 사용할 수 있습니다. API 키나 비밀번호를 소스에 직접 적어 GitHub에 올리지 마세요.

## 개발자 로컬 실행

```powershell
py -m pip install -r requirements.txt
py -m streamlit run app.py
```

브라우저에서 `http://localhost:8501`로 접속하세요. 별도 FastAPI 프로세스는 띄우지 않습니다. 기존 PC에서 사용하는 `8000`/`8001` 포트와 충돌하지 않도록 내부 API는 **8765번**을 사용합니다.

백엔드 단독 자동 검증:

```powershell
py -m pip install httpx
py -m unittest discover -s tests -v
```

## 중요한 제한 사항

- **실제 배포 URL은 GitHub 및 Streamlit 계정에서 Deploy를 누른 후에만 생성됩니다.** 이 ZIP 자체는 온라인에 게시된 사이트가 아닙니다.
- **로컬 SQLite는 임시 저장**입니다. 무료 호스팅에서 재시작·재배포 시 실험 기록이 없어질 수 있습니다. 실제 데이터를 지속 보관하려면 외부 DB(Postgres 등)와 백업을 연결하세요.
- 이 배포는 Streamlit 화면만 공개합니다. FastAPI는 호스팅 내부 `127.0.0.1:8765`에만 바인딩되므로 **다른 팀원의 컴퓨터에서 HTTP POST로 직접 호출할 수 없습니다.** 팀원에게서 받은 결과를 관리자 UI에서 등록할 수 있지만, **완전 자동 팀원 연동**을 하려면 인증된 별도 외부 API를 구축해야 합니다.
- 정답 ID를 통한 채점은 **검증된 완전한 정답 목록**을 전제로 합니다. AI가 추가로 제보한 미등록 취약점은 **오탐 확정이 아니라 추가 확인 필요**로 취급합니다.
- 조합별 예상 병렬 시간은 개별 실행시간의 최대값으로 계산한 **추정치**입니다. 실측 조합 처리 시간이 아닙니다.
- **실제 기업 시스템이나 민감한 로그·비밀키를 공개 앱에 입력하지 마세요.** 허가된 교육용 격리 환경의 데이터만 사용하세요.

## 기술 구성

- `app.py`: Streamlit 대시보드 및 내부 FastAPI 서버 자동 실행
- `backend.py`: 루프백 전용 FastAPI
- `combo_eval_api.py`: 성능 평가·조합 추천 API 및 SQLite 저장
- `model_contributions.py`: 발견 항목·기여도·근거 표시
- `requirements.txt`: 서버에 설치할 패키지 목록
- `.streamlit/config.toml`: 다크 테마
- `.streamlit/secrets.toml.example`: 관리자 비밀번호 예시 (**실제 비밀번호를 적어 업로드하면 안 됨**)
- `tests/test_api.py`: 기본 API 평가·보고서 테스트
