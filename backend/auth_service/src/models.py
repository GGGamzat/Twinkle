from sqlalchemy import Column, String, Text, Boolean, DateTime, Integer, func, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from src.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    phone_number = Column(String(20), unique=True, nullable=True, index=True)
    password_hash = Column(String(255), nullable=False)

    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)

    provider = Column(String, nullable=False)  # google / github
    provider_id = Column(String, nullable=False)

    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    permissions = relationship("UserPermission", back_populates="user", cascade="all, delete-orphan")


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(String(100), primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)


class UserPermission(Base):
    __tablename__ = "user_permissions"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    permission_id = Column(String(100), ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)

    user = relationship("User", back_populates="permissions")
    permission = relationship("Permission")