from pydantic import BaseModel, EmailStr, constr, field_validator
import re
from typing import Optional
from sqlalchemy import Column, Boolean ,Integer, String, DateTime, Float, ForeignKey, func
from sqlalchemy.orm import declarative_base , relationship
from sqlalchemy.sql import func

from datetime import datetime
from enum import Enum


Base = declarative_base()

class CategorySchema(BaseModel):
    category_name: str
    parent_category_id: Optional[int] = None

class ProductSchema(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    stock: int
    category_id: int
    image_url: Optional[str] = None

#payments
class PaymentRequest(BaseModel):
    order_id: int
    user_id: int
    gateway: str
    amount: float
    payment_method: str
    currency: str = "INR"

class PaymentVerificationRequest(BaseModel):
    order_id: str
    payment_id: str
    signature: str


#
class Payment(Base):
    __tablename__ = "payments"

    user_name = Column(String(100), nullable=True)
    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, index=True)
    amount = Column(Float)
    currency = Column(String(10), default="INR")
    transaction_id = Column(String(255), unique=True, index=True)
    status = Column(String(20))
    user_email = Column(String(255))
    user_phone = Column(String(20))
    payment_method = Column(String(50))
    retry_count = Column(Integer, default=0)
    last_attempt = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now())
    user_id = Column(Integer, nullable=True)

    def __repr__(self):
        return f"<Payment(id={self.id}, amount={self.amount}, status={self.status}, method={self.payment_method})>"




# Pydantic models for Razorpay Webhook Payload
class PaymentEntity(BaseModel):
    amount: int
    currency: str
    status: str
    email: Optional[str] = "unknown"
    contact: Optional[str] = "unknown"
    method: Optional[str] = None

class PaymentPayload(BaseModel):
    entity: PaymentEntity

# This is now used directly for handling Razorpay Webhook data
class RazorpayWebhookPayload(BaseModel):
    payload: PaymentPayload



class BannerStatus(str, Enum):
    active = "active"
    inactive = "inactive"

class BannerBase(BaseModel):
    title: str
    image_url: str
    link_url: str
    status: BannerStatus = BannerStatus.active
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None

class BannerCreate(BannerBase):
    pass

class BannerUpdate(BannerBase):
    pass

class BannerInDB(BannerBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True  # For SQLAlchemy integration
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class BannerResponse(BaseModel):
    id: int
    title: str
    image_url: str
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    mobile: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    mobile: str
    role: str
    class Config:
        from_attributes = True

class TokenData(BaseModel):
    email: Optional[EmailStr] = None


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    mobile = Column(String(20), unique=True, nullable=False)
    password = Column(String(128), nullable=False)
    role = Column(String(20), nullable=False, default='assistant')
    is_active = Column(Boolean, default=True)

    active_tokens = relationship("ActiveTokens", backref="user", cascade="all, delete-orphan")


class TokenBlocklist(Base):
    __tablename__ = "token_blocklist"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(255), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role = Column(String(50))
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

class ActiveTokens(Base):
    __tablename__ = "active_tokens"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(255), nullable=False, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role = Column(String(50))
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class SignupModel(BaseModel):
    username: constr(strip_whitespace=True, min_length=1)
    email: EmailStr
    mobile: constr(strip_whitespace=True, min_length=8, max_length=15)
    password: constr(min_length=8)
    secret_code: Optional[str] = None
    @field_validator('mobile', mode='before')
    @classmethod
    def validate_mobile(cls, v):
        pattern = re.compile(r'^\+?[1-9]\d{7,14}$')
        if not pattern.match(v):
            raise ValueError('Invalid mobile number format')
        return v

    @field_validator('password', mode='before')
    @classmethod
    def validate_password(cls, v):
        if (len(v) < 8 or
            not any(c.isupper() for c in v) or
            not any(c.islower() for c in v) or
            not any(c.isdigit() for c in v) or
            not any(c in "!@#$%^&*()-_=+[{]};:'\",<.>/?\\|" for c in v)):
            raise ValueError('Password must contain 8+ characters with uppercase, lowercase, number, and special character')
        return v

class LoginModel(BaseModel):
    identifier: constr(strip_whitespace=True, min_length=1)
    password: constr(min_length=1)

class UserResponseModel(BaseModel):
    username: str
    email: EmailStr
    mobile: str

class LoginRequest(BaseModel):
    identifier: str
    password: str

class SignupModel(BaseModel):
    username: str
    email: str
    mobile: str
    password: str
    role: Optional[str] = "user"  # default to "user"
    secret_code: Optional[str] = None


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    is_active: Optional[bool] = None
    role: str

    class Config:
        from_attributes = True
