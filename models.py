from sqlalchemy import Column, Integer, String, DateTime, Enum as SQLEnum
from sqlalchemy.sql import func
from database import Base
import enum


class IOCType(str, enum.Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash = "hash"


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    ioc = Column(String, nullable=False)
    type = Column(SQLEnum(IOCType), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())