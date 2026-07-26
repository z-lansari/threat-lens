from fastapi import FastAPI
from pydantic import BaseModel
from enum import Enum

app = FastAPI()

class IOCType(str, Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash = "hash"

class IOCRequest(BaseModel):
    ioc: str
    type: IOCType

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/analyze")
def analyze_ioc(request: IOCRequest):
    return {"received_ioc": request.ioc, "received_type": request.type}