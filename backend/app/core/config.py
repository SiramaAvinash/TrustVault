import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator

BASE_DIR = Path(__file__).resolve().parents[2]

class Settings(BaseSettings):
    resend_api_key: str = ""
    resend_from_email: str = "onboarding@resend.dev"
    login_otp_every_time: bool = False
    jwt_secret: str = "LOCAL-ONLY-CHANGE-ME"
    environment: str = "development"
    google_client_id: str = ""
    database_url: str = "sqlite:///./trustvault.db"
    storage_dir: str = "./storage"
    max_upload_mb: int = 10
    access_token_minutes: int = 30
    frontend_origin: str = "http://localhost:5173"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_use_tls: bool = True
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    @model_validator(mode="after")
    def validate_production_secrets(self):
        if self.environment.lower() in {"production", "prod"}:
            if (self.jwt_secret == "LOCAL-ONLY-CHANGE-ME"
                    or self.jwt_secret.lower().startswith(("replace-with", "change-me", "your-"))
                    or len(self.jwt_secret) < 32):
                raise ValueError("Production requires a unique JWT_SECRET of at least 32 characters")
        if self.max_upload_mb < 1 or self.max_upload_mb > 100:
            raise ValueError("MAX_UPLOAD_MB must be between 1 and 100")
        if self.access_token_minutes < 5 or self.access_token_minutes > 1440:
            raise ValueError("ACCESS_TOKEN_MINUTES must be between 5 and 1440")
        return self

settings = Settings()
storage_path = Path(settings.storage_dir)
if not storage_path.is_absolute():
    storage_path = (Path.cwd() / storage_path).resolve()
storage_path.mkdir(parents=True, exist_ok=True)
