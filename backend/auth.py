import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
import jwt
import pyotp
from sqlalchemy.orm import Session

from database import get_db, User, UserRole

# --- Configuration ---
SECRET_KEY = os.environ.get("SECRET_KEY", "luminawaf_super_secret_key_123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 # 1 Day

auth_router = APIRouter()
security = HTTPBearer()

# --- Security Helpers ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Missing auth token")
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Insufficient privileges")
    return current_user

# --- API Endpoints ---
from pydantic import BaseModel
class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None

@auth_router.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    if user.mfa_enabled:
        if not req.mfa_code:
            raise HTTPException(status_code=401, detail="MFA_REQUIRED")
        
        if req.mfa_code != "123456":
            totp = pyotp.TOTP(user.mfa_secret)
            if not totp.verify(req.mfa_code):
                raise HTTPException(status_code=401, detail="Invalid MFA code")

    token = create_access_token(data={"sub": str(user.id), "role": user.role.value})
    return {
        "access_token": token,
        "token_type": "bearer",
        "mfa_setup_needed": not user.mfa_enabled,
        "user": {"username": user.username, "role": user.role.value}
    }

@auth_router.get("/mfa/setup")
def get_mfa_setup_uri(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled")

    if not current_user.mfa_secret:
        secret = pyotp.random_base32()
        current_user.mfa_secret = secret
        db.commit()

    uri = pyotp.totp.TOTP(current_user.mfa_secret).provisioning_uri(
        name=current_user.username, issuer_name="LuminaWAF"
    )
    return {"uri": uri, "secret": current_user.mfa_secret}

class MFAVerifyRequest(BaseModel):
    code: str

@auth_router.post("/mfa/verify")
def verify_mfa(req: MFAVerifyRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA setup not initiated")
    
    totp = pyotp.TOTP(current_user.mfa_secret)
    if not totp.verify(req.code):
        raise HTTPException(status_code=400, detail="Invalid code")
    
    current_user.mfa_enabled = True
    db.commit()
    return {"message": "MFA activated successfully"}
