from typing import Optional, Tuple
from datetime import timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_
from fastapi import HTTPException, status

from src.models import User, UserStatus
from src.schemas import UserCreate, Token
from src.security import (
    verify_password, get_password_hash,
    create_access_token, create_refresh_token
)
from src.utils import send_verification_email, send_password_reset_email
from src.config import settings


class AuthService:
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def _get_user_by_id(self, user_id: int) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
    
    async def _get_user_by_email(self, email: str) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()
    
    async def _get_user_by_username(self, username: str) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(User.username == username)
        )
        return result.scalar_one_or_none()
    
    async def _get_user_by_email_or_username(self, email_or_username: str) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(
                or_(
                    User.email == email_or_username,
                    User.username == email_or_username
                )
            )
        )
        return result.scalar_one_or_none()
    
    async def _get_user_by_oauth(self, provider: str, oauth_id: str) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(
                and_(
                    User.oauth_provider == provider,
                    User.oauth_id == oauth_id
                )
            )
        )
        return result.scalar_one_or_none()
    
    async def _email_exists(self, email: str) -> bool:
        result = await self.session.execute(
            select(User.id).where(User.email == email).limit(1)
        )
        return result.scalar_one_or_none() is not None
    
    async def _username_exists(self, username: str) -> bool:
        result = await self.session.execute(
            select(User.id).where(User.username == username).limit(1)
        )
        return result.scalar_one_or_none() is not None
    
    async def _generate_unique_username(self, base_username: str) -> str:
        username = base_username
        counter = 1
        
        while await self._username_exists(username):
            username = f"{base_username}_{counter}"
            counter += 1
        
        return username
    
    async def _create_user(self, **kwargs) -> User:
        user = User(**kwargs)
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return user
    
    async def _update_user(self, user_id: int, **kwargs) -> Optional[User]:
        stmt = (
            update(User)
            .where(User.id == user_id)
            .values(**kwargs)
            .returning(User)
        )
        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.scalar_one_or_none()
    

    async def register_user(self, user_data: UserCreate) -> User:
        if await self._email_exists(user_data.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        if await self._username_exists(user_data.username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken"
            )
        
        hashed_password = get_password_hash(user_data.password)
        user = await self._create_user(
            username=user_data.username,
            email=user_data.email,
            password=hashed_password,
            is_verified=False,
            status=UserStatus.ACTIVE
        )
        
        # Отправка email для верификации
        await self._send_verification_email(user)
        
        return user
    
    async def authenticate_user(self, username: str, password: str) -> Tuple[User, Token]:
        user = await self._get_user_by_email_or_username(username)
        
        if not user or not user.password or not verify_password(password, user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        if user.status != UserStatus.ACTIVE:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is {user.status.value}"
            )
        
        tokens = self._create_tokens(user)
        return user, tokens
    
    async def authenticate_oauth_user(
        self, 
        email: str, 
        provider: str, 
        oauth_id: str,
        username: Optional[str] = None
    ) -> Tuple[User, Token]:
        # Ищем по OAuth ID
        user = await self._get_user_by_oauth(provider, oauth_id)
        
        if not user:
            # Ищем по email
            user = await self._get_user_by_email(email)
            
            if user:
                # Обновляем существующего пользователя
                user.oauth_provider = provider
                user.oauth_id = oauth_id
                if not user.is_verified:
                    user.is_verified = True
                await self.session.commit()
            else:
                # Создаем нового пользователя
                if not username:
                    username = email.split('@')[0]
                
                unique_username = await self._generate_unique_username(username)
                
                user = await self._create_user(
                    username=unique_username,
                    email=email,
                    oauth_provider=provider,
                    oauth_id=oauth_id,
                    is_verified=True,
                    status=UserStatus.ACTIVE
                )
        
        if user.status != UserStatus.ACTIVE:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is {user.status.value}"
            )
        
        tokens = self._create_tokens(user)
        return user, tokens
    
    async def verify_email(self, user_id: int) -> bool:
        user = await self._get_user_by_id(user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already verified"
            )
        
        await self._update_user(user_id, is_verified=True)
        return True
    
    async def resend_verification_email(self, email: str) -> bool:
        user = await self._get_user_by_email(email)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already verified"
            )
        
        await self._send_verification_email(user)
        return True
    
    async def initiate_password_reset(self, email: str) -> bool:
        user = await self._get_user_by_email(email)
        
        if user and user.status == UserStatus.ACTIVE:
            token = create_access_token(
                {"sub": str(user.id), "purpose": "password_reset"},
                expires_delta=timedelta(hours=1)
            )
            await send_password_reset_email(user.email, token)
        
        return True
    
    async def reset_password(self, user_id: int, new_password: str) -> bool:
        user = await self._get_user_by_id(user_id)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if user.status != UserStatus.ACTIVE:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is not active"
            )
        
        hashed_password = get_password_hash(new_password)
        await self._update_user(user_id, password=hashed_password)
        return True
    
    async def change_password(self, user_id: int, current_password: str, new_password: str) -> bool:
        user = await self._get_user_by_id(user_id)
        
        if not user or not user.password:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if not verify_password(current_password, user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect"
            )
        
        hashed_password = get_password_hash(new_password)
        await self._update_user(user_id, password=hashed_password)
        return True
    
    # Вспомогательные методы
    def _create_tokens(self, user: User) -> Token:
        access_token = create_access_token(
            data={"sub": str(user.id), "username": user.username}
        )
        refresh_token = create_refresh_token(
            data={"sub": str(user.id)}
        )
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
    
    async def _send_verification_email(self, user: User) -> None:
        token = create_access_token(
            {"sub": str(user.id), "email": user.email, "purpose": "email_verification"}
        )
        await send_verification_email(user.email, token)
    
    def validate_refresh_token(self, refresh_token: str) -> Token:
        from app.core.security import verify_token
        
        payload = verify_token(refresh_token)
        
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Создаем новые токены
        access_token = create_access_token(
            data={"sub": user_id, "username": payload.get("username", "")}
        )
        new_refresh_token = create_refresh_token(
            data={"sub": user_id}
        )
        
        return Token(
            access_token=access_token,
            refresh_token=new_refresh_token
        )