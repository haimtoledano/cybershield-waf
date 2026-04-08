import os
from sqlalchemy import create_engine, Column, String, Boolean, Enum, Integer, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.orm import sessionmaker
from enum import Enum as EEnum
import uuid

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://waf_admin:waf_password@db:5432/waf_db")

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class WAFMode(str, EEnum):
    Blocking = 'Blocking'
    Logging = 'Logging'
    Disabled = 'Disabled'

class HeaderDirection(str, EEnum):
    Request = 'Request'
    Response = 'Response'

class UserRole(str, EEnum):
    admin = "admin"
    viewer = "viewer"

class User(Base):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.viewer, nullable=False)
    mfa_secret = Column(String, nullable=True)
    mfa_enabled = Column(Boolean, default=False)

class VirtualServer(Base):
    __tablename__ = "virtual_servers"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, index=True)
    ingress_port = Column(Integer, unique=True)
    backend_target = Column(String)
    active = Column(Boolean, default=True)
    waf_mode = Column(Enum(WAFMode), nullable=False, default=WAFMode.Disabled)
    log_retention_days = Column(Integer, default=7)
    rate_limit_enabled = Column(Boolean, default=False)
    rate_limit_rpm = Column(Integer, default=100)

    exclusions = relationship("RuleExclusion", back_populates="virtual_server", cascade="all, delete-orphan")
    profiles = relationship("VirtualServerProfile", back_populates="virtual_server", cascade="all, delete-orphan")
    headers = relationship("CustomHeader", back_populates="virtual_server", cascade="all, delete-orphan")

class VirtualServerProfile(Base):
    __tablename__ = "virtual_server_profiles"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vs_id = Column(String(36), ForeignKey('virtual_servers.id'))
    profile_name = Column(String, index=True)

    virtual_server = relationship("VirtualServer", back_populates="profiles")

class RuleExclusion(Base):
    __tablename__ = "rule_exclusions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vs_id = Column(String(36), ForeignKey('virtual_servers.id'))
    path_pattern = Column(String, index=True)
    rule_type = Column(String)  # 'SQLi', 'XSS', or 'ALL'
    
    virtual_server = relationship("VirtualServer", back_populates="exclusions")

class CustomHeader(Base):
    __tablename__ = "custom_headers"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vs_id = Column(String(36), ForeignKey('virtual_servers.id'))
    direction = Column(Enum(HeaderDirection), nullable=False)
    header_key = Column(String, index=True)
    header_value = Column(String)

    virtual_server = relationship("VirtualServer", back_populates="headers")

from datetime import datetime
from sqlalchemy import DateTime, Text

class AccessLog(Base):
    __tablename__ = "access_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    vs_id = Column(String(36), index=True) # Soft link to virtual server ID
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    method = Column(String(10))
    path = Column(String)
    status_code = Column(Integer, index=True)
    client_ip = Column(String(50))
    user_agent = Column(String)
    req_payload = Column(Text, nullable=True) # Up to 10kb of request body
    resp_payload = Column(Text, nullable=True) # Up to 10kb of response body
    block_reason = Column(String, nullable=True) # Envoy RESPONSE_CODE_DETAILS

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
