from fastapi import FastAPI, Depends
from pydantic import BaseModel
from enum import Enum
from sqlalchemy.orm import Session
from database import SessionLocal
from models import IOC
import virustotal
import abuseipdb

app = FastAPI()


class IOCType(str, Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash = "hash"


class IOCRequest(BaseModel):
    ioc: str
    type: IOCType


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/analyze")
def analyze_ioc(request: IOCRequest, db: Session = Depends(get_db)):
    new_ioc = IOC(ioc=request.ioc, type=request.type)
    db.add(new_ioc)
    db.commit()
    db.refresh(new_ioc)

    vt_result = None
    abuse_result = None
    if request.type == "ip":
        vt_result = virustotal.check_ip(request.ioc)
        abuse_result = abuseipdb.check_ip(request.ioc)

    return {
        "id": new_ioc.id,
        "ioc": new_ioc.ioc,
        "type": new_ioc.type,
        "created_at": new_ioc.created_at,
        "virustotal": vt_result,
        "abuseipdb": abuse_result
    }


@app.get("/history")
def get_history(db: Session = Depends(get_db)):
    iocs = db.query(IOC).all()
    return iocs