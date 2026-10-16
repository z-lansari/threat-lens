from fastapi import FastAPI, Depends, HTTPException
from validators import validate_ioc
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
    if not validate_ioc(request.ioc, request.type.value):
        raise HTTPException(
            status_code=422,
            detail=f"'{request.ioc}' is not a valid {request.type.value}"
        )
    new_ioc = IOC(ioc=request.ioc, type=request.type)
    db.add(new_ioc)
    db.commit()
    db.refresh(new_ioc)

    vt_result = None
    abuse_result = None
    if request.type == "ip":
        vt_result = virustotal.check_ip(request.ioc)
        abuse_result = abuseipdb.check_ip(request.ioc)
    elif request.type == "domain":
        vt_result = virustotal.check_domain(request.ioc)
    elif request.type == "hash":
        vt_result = virustotal.check_hash(request.ioc)
    elif request.type == "url":
        vt_result = virustotal.check_url(request.ioc) 

    new_ioc.virustotal_result = vt_result
    new_ioc.abuseipdb_result = abuse_result
    db.commit()     
      
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