from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

app = FastAPI(title="SHADOW CORE Demo Dashboard")
app.mount("/static", StaticFiles(directory="static"), name="static")


class ImprovementAction(BaseModel):
    action: str = Field(min_length=1, max_length=500)
    test: str = Field(min_length=1, max_length=200)


@app.get("/", response_class=FileResponse)
def index():
    return FileResponse("static/index.html")


@app.get("/app.js", response_class=FileResponse)
def javascript():
    return FileResponse("static/app.js", media_type="application/javascript")


@app.get("/api/dashboard")
def dashboard():
    # No fabricated test results or coverage claims; connect a real test-run store separately.
    return {
        "status": "demo_no_test_results_configured",
        "total": 0,
        "passed": 0,
        "tests": [],
        "coverage": None,
        "merkle_root": None,
    }


@app.get("/api/economia-ataque")
def attack_economics():
    return {"status": "not_configured", "message": "No independently verified cost data is configured."}


@app.post("/api/accion-mejora")
def save_improvement_action(action: ImprovementAction):
    # Demo response only: intentionally does not write arbitrary user input to cloud services.
    return {"status": "received_demo_only", "action": action.model_dump()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
