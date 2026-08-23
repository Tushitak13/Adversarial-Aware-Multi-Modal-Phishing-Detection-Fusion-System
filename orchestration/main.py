from fastapi import FastAPI
from orchestration.pipeline import run_pipeline

app = FastAPI()


@app.post("/analyze")
def analyze(url: str, scenario: str = "all_agree_safe"):
    result = run_pipeline(url, scenario)
    return result