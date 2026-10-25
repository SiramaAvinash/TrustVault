from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class GoogleLoginRequest(BaseModel):
    credential: str = Field(min_length=20, max_length=10000)


class RegisterRequest(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=12, max_length=128)
    @field_validator("password")
    @classmethod
    def strong_password(cls, value):
        if not any(c.islower() for c in value) or not any(c.isupper() for c in value) or not any(c.isdigit() for c in value):
            raise ValueError("Password must include uppercase, lowercase, and a number")
        return value

class OTPVerifyRequest(BaseModel):
    email: EmailStr
    code: str = Field(pattern=r"^\d{6}$")

class UserOut(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    two_factor_enabled: bool = False
    model_config = ConfigDict(from_attributes=True)

class DocumentOut(BaseModel):
    id: int
    title: str
    category: str
    original_filename: str
    content_type: str
    size_bytes: int
    sha256: str
    owner_id: int
    owner_name: str
    created_at: datetime
    updated_at: datetime
    permission: str
