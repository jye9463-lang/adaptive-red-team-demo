"""Internal local-only benchmark API for Streamlit Community Cloud.

This is *not* a public attack/scanning API. Imported from the Streamlit process
and served via a loopback-only background uvicorn thread.
"""

from fastapi import FastAPI
from combo_eval_api import router, seed_demo

app = FastAPI(title="Adaptive Red Team: benchmark API", docs_url=None, redoc_url=None)
app.include_router(router)


@app.get("/")
def home():
    return {"message": "Adaptive Red Team 서버 실행 성공!", "mode": "local-only"}


@app.get("/experiments")
def get_legacy_experiments():
    # Data from the user's local PC is intentionally not included in the cloud demo.
    return {"experiments": []}


# Seed a known synthetic dataset for judges to view without creating a run.
seed_demo()
