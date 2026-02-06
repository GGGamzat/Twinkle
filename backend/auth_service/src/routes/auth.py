from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from src.database import get_db
from src.schemas import (
    UserCreate, UserResponse, Token,
    EmailVerification, PasswordReset, PasswordResetConfirm
)
from src.services.auth_service import AuthService
from src.security import verify_token

router = APIRouter(prefix="/auth", tags=["authentication"])

# Dependency для получения текущего пользователя
async def get_current_user(
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db)
) -> int:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing"
        )
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme"
            )
        
        payload = verify_token(token)
        user_id = int(payload.get("sub"))
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        return user_id
        
    except (ValueError, AttributeError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    auth_service = AuthService(db)
    try:
        user = await auth_service.register_user(user_data)
        return user
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@router.post("/login", response_model=Token)
async def login(
    username: str,
    password: str,
    db: AsyncSession = Depends(get_db)
):
    auth_service = AuthService(db)
    try:
        _, tokens = await auth_service.authenticate_user(username, password)
        return tokens
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str
):
    auth_service = AuthService(None)  # Session не нужна для валидации токена
    try:
        tokens = auth_service.validate_refresh_token(refresh_token)
        return tokens
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )

@router.post("/verify-email")
async def verify_email(
    token: str,
    db: AsyncSession = Depends(get_db)
):
    try:
        payload = verify_token(token)
        
        if payload.get("purpose") != "email_verification":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token purpose"
            )
        
        user_id = int(payload.get("sub"))
        auth_service = AuthService(db)
        
        await auth_service.verify_email(user_id)
        return {"message": "Email verified successfully"}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token"
        )

@router.post("/resend-verification")
async def resend_verification(
    email_data: EmailVerification,
    db: AsyncSession = Depends(get_db)
):
    auth_service = AuthService(db)
    try:
        await auth_service.resend_verification_email(email_data.email)
        return {"message": "Verification email sent"}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification email"
        )

@router.post("/forgot-password")
async def forgot_password(
    email_data: PasswordReset,
    db: AsyncSession = Depends(get_db)
):
    auth_service = AuthService(db)
    try:
        await auth_service.initiate_password_reset(email_data.email)
        return {"message": "If email exists, reset link will be sent"}
    except Exception as e:
        # Всегда возвращаем успех для безопасности
        return {"message": "If email exists, reset link will be sent"}

@router.post("/reset-password")
async def reset_password(
    reset_data: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db)
):
    try:
        payload = verify_token(reset_data.token)
        
        if payload.get("purpose") != "password_reset":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token purpose"
            )
        
        user_id = int(payload.get("sub"))
        auth_service = AuthService(db)
        
        await auth_service.reset_password(user_id, reset_data.new_password)
        return {"message": "Password reset successful"}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token"
        )

@router.post("/change-password")
async def change_password(
    current_password: str,
    new_password: str,
    current_user_id: int = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    auth_service = AuthService(db)
    try:
        await auth_service.change_password(
            current_user_id, 
            current_password, 
            new_password
        )
        return {"message": "Password changed successfully"}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password"
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user_id: int = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    from app.services.user_service import UserService
    user_service = UserService(db)
    try:
        user = await user_service.get_user_by_id(current_user_id)
        return user
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get user info"
        )