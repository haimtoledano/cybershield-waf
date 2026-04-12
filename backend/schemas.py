from pydantic import BaseModel
from enum import Enum as EEnum
from typing import Optional, List
from datetime import datetime

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
    is_online: bool = True
    last_check: Optional[datetime] = None

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



class GlobalSettingsBase(BaseModel):
    setting_key: str
    setting_value: Optional[str] = None
    description: Optional[str] = None

class GlobalSettingsRead(GlobalSettingsBase):
    id: str

    class Config:
        from_attributes = True

class AuditLogRead(BaseModel):
    id: str
    timestamp: datetime
    user_id: Optional[str] = None
    username: Optional[str] = None
    action: str
    details: Optional[str] = None

    class Config:
        from_attributes = True

class SystemStatsRead(BaseModel):
    total_requests_24h: int
    total_blocked_24h: int
    active_virtual_servers: int
    active_blacklisted_ips: int

class TopItem(BaseModel):
    key: str
    count: int

class ReportPreviewRead(BaseModel):
    total_requests: int
    total_blocked: int
    top_ips: List[TopItem]
    top_reasons: List[TopItem]
    status_distribution: List[TopItem]

class ReportSubscriptionBase(BaseModel):
    frequency: str # 'daily', 'weekly'

class ReportSubscriptionRead(ReportSubscriptionBase):
    id: str
    user_id: str
    last_sent: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True

class ReportSubscriptionCreate(ReportSubscriptionBase):
    pass
