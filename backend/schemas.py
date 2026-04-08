from pydantic import BaseModel
from enum import Enum as EEnum
from typing import Optional, List

class WAFMode(str, EEnum):
    Blocking = 'Blocking'
    Logging = 'Logging'
    Disabled = 'Disabled'

class HeaderDirection(str, EEnum):
    Request = 'Request'
    Response = 'Response'

class VirtualServerBase(BaseModel):
    name: str
    ingress_port: int
    backend_target: str
    active: bool = True
    waf_mode: WAFMode = WAFMode.Disabled
    log_retention_days: int = 7
    rate_limit_enabled: bool = False
    rate_limit_rpm: int = 100

class VirtualServerCreate(VirtualServerBase):
    profiles: List[str] = []

class VirtualServerUpdate(BaseModel):
    name: Optional[str] = None
    ingress_port: Optional[int] = None
    backend_target: Optional[str] = None
    active: Optional[bool] = None
    waf_mode: Optional[WAFMode] = None
    log_retention_days: Optional[int] = None
    rate_limit_enabled: Optional[bool] = None
    rate_limit_rpm: Optional[int] = None
    profiles: Optional[List[str]] = None

class ProfileRead(BaseModel):
    id: str
    profile_name: str

    class Config:
        from_attributes = True

class VirtualServerRead(VirtualServerBase):
    id: str

    class Config:
        from_attributes = True

class RuleExclusionCreate(BaseModel):
    path_pattern: str
    rule_type: str

class RuleExclusionRead(RuleExclusionCreate):
    id: str
    vs_id: str

    class Config:
        from_attributes = True

class CustomHeaderCreate(BaseModel):
    direction: HeaderDirection
    header_key: str
    header_value: str

class CustomHeaderRead(CustomHeaderCreate):
    id: str
    vs_id: str

    class Config:
        from_attributes = True

class VirtualServerWithExclusions(VirtualServerRead):
    exclusions: List[RuleExclusionRead] = []
    profiles: List[ProfileRead] = []
    headers: List[CustomHeaderRead] = []

    class Config:
        from_attributes = True
