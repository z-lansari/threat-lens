from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class IOCRequest(BaseModel):
    ioc: str
    type: str

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/analyze")
def analyze_ioc(request: IOCRequest):
    return {"received_ioc": request.ioc, "received_type": request.type}