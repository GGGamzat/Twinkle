from sqlalchemy import Column, String, Text, Boolean, DateTime, Integer, func, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from src.database import Base


class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DELETED = "deleted"
    BANNED = "banned"

class OAuthProvider(str, enum.Enum):
    GOOGLE = "google"
    GITHUB = "github"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=True)
    status = Column(PGEnum(UserStatus, name="user_status"), default=UserStatus.ACTIVE)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    oauth_provider = Column(String, nullable=True)
    oauth_id = Column(String, nullable=True, unique=True)

    profile_id = Column(String, unique=True, nullable=True)
    
    def __repr__(self):
        return f"<User {self.username}>"