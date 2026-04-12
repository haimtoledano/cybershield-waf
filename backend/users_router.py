from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy.orm import Session
from database import get_db, User, UserRole
from auth import require_admin, get_password_hash

users_router = APIRouter()

class UserCreate(BaseModel):
    username: str
    password: str
    role: str
    email: Optional[str] = None

class UserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None

class UserPasswordUpdate(BaseModel):
    password: str

class UserRead(BaseModel):
    id: str
    username: str
    role: str
    email: Optional[str] = None
    mfa_enabled: bool

@users_router.get("/", response_model=List[UserRead], summary="List all users")
def list_users(db: Session = Depends(get_db), current_admin: User = Depends(require_admin)):
    users = db.query(User).all()
    return [{"id": str(u.id), "username": u.username, "role": u.role.value, "email": u.email, "mfa_enabled": u.mfa_enabled} for u in users]

@users_router.post("/", response_model=UserRead, status_code=status.HTTP_201_CREATED, summary="Create a new user")
def create_user(new_user_data: UserCreate, db: Session = Depends(get_db), current_admin: User = Depends(require_admin)):
    if len(new_user_data.password) < 4:
        raise HTTPException(status_code=400, detail="Password too short")
    existing_user = db.query(User).filter(User.username == new_user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")
        
    hashed_password = get_password_hash(new_user_data.password)
    
    new_user = User(
        username=new_user_data.username,
        role=UserRole(new_user_data.role),
        email=new_user_data.email,
        hashed_password=hashed_password,
        mfa_enabled=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"id": str(new_user.id), "username": new_user.username, "role": new_user.role.value, "email": new_user.email, "mfa_enabled": new_user.mfa_enabled}

@users_router.delete("/{user_id}", summary="Delete a user by ID")
def delete_user(user_id: str, db: Session = Depends(get_db), current_admin: User = Depends(require_admin)):
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")
        
    if user_to_delete.id == current_admin.id:
        raise HTTPException(status_code=403, detail="Cannot delete your own admin account")
        
    db.delete(user_to_delete)
    db.commit()
    return {"status": "deleted"}

@users_router.put("/{user_id}", response_model=UserRead, summary="Update user details (Admin)")
def update_user(user_id: str, update_data: UserUpdate, db: Session = Depends(get_db), current_admin: User = Depends(require_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if update_data.email is not None:
        user.email = update_data.email
    if update_data.role is not None:
        if user.id == current_admin.id and update_data.role != 'admin':
            raise HTTPException(status_code=400, detail="Cannot demote yourself")
        user.role = UserRole(update_data.role)
        
    db.commit()
    db.refresh(user)
    return {"id": str(user.id), "username": user.username, "role": user.role.value, "email": user.email, "mfa_enabled": user.mfa_enabled}

@users_router.post("/{user_id}/mfa/reset", summary="Reset MFA for a user (Admin)")
def reset_user_mfa(user_id: str, db: Session = Depends(get_db), current_admin: User = Depends(require_admin)):
    import pyotp
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    secret = pyotp.random_base32()
    user.mfa_secret = secret
    user.mfa_enabled = False
    db.commit()
    
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="LuminaWAF")
    return {"uri": uri, "secret": secret}

from auth import get_current_user

@users_router.put("/me/password", summary="Update completely own password")
def update_my_password(data: UserPasswordUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user.mfa_enabled:
        raise HTTPException(status_code=403, detail="MFA must be set up and enabled to change your password.")
    if len(data.password) < 4:
        raise HTTPException(status_code=400, detail="Password too short")
        
    current_user.hashed_password = get_password_hash(data.password)
    db.commit()
    return {"status": "success", "detail": "Password updated successfully"}
