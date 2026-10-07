from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    APP_NAME: str = "ScamShield AI"
    APP_ENV: str = "development"
    SECRET_KEY: str = "dev-secret-key-change-in-production"

    DATABASE_URL: str = "sqlite+aiosqlite:///./scamshield.db"

    OPENAI_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""

    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # Rate limiting
    RATE_LIMIT_ANON: str = "10/minute"
    RATE_LIMIT_AUTH: str = "60/minute"

    # JWT
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    @property
    def origins_list(self) -> List[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",")]

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
