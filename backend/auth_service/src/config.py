from pydantic import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/auth_service_db"

    JWT_SECRET_KEY: str = "my_secret_key"
    JWT_ALGORITHM: str = "HS256"

    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str

    GITHUB_CLIENT_ID: str
    GITHUB_CLIENT_SECRET: str

    FRONTEND_URL: str = "http://localhost:3000"
    BACKEND_URL: str = "http://localhost:8000"

settings = Settings()