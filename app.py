import re
import html
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict

from fastapi import FastAPI, HTTPException, Status, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr, field_validator
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ==========================================
# 1. CẤU HÌNH BẢO MẬT & MÃ HÓA (CRYPTOGRAPHY)
# ==========================================

# Salt tĩnh (Pepper) kết hợp cùng Dynamic Salt ngầm định của Argon2id
PEPPER = "StaticPepperSecret_2026_SecurePepperKey!@#"

# Băm mật khẩu Argon2id
ph = PasswordHasher()

# Tạo cặp khóa mã hóa RSA 2048-bit ký & xác thực JWT (RS256)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

PEM_PRIVATE_KEY = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

PEM_PUBLIC_KEY = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Cơ sở dữ liệu tạm thời (In-memory storage)
users_db: Dict[str, dict] = {}
reset_tokens_db: Dict[str, dict] = {}

app = FastAPI(title="Core Auth & Cryptography System")

# ==========================================
# 2. TIỆN ÍCH MÁ HÓA & KIỂM TRA ĐẦU VÀO
# ==========================================

def hash_password_with_pepper(password: str) -> str:
    """Băm mật khẩu sử dụng Argon2id kết hợp Pepper tĩnh & Salt động."""
    combined = password + PEPPER
    return ph.hash(combined)

def verify_password_with_pepper(hash_str: str, password: str) -> bool:
    """Xác thực mật khẩu Argon2id."""
    try:
        combined = password + PEPPER
        return ph.verify(hash_str, combined)
    except (VerifyMismatchError, VerificationError):
        return False

def validate_password_complexity(password: str):
    """
    Chuẩn hóa độ phức tạp mật khẩu:
    - Độ dài tối thiểu 8 ký tự
    - Ít nhất 1 chữ hoa, 1 chữ thường, 1 số, 1 ký tự đặc biệt
    """
    if len(password) < 8:
        raise ValueError("Mật khẩu phải có độ dài tối thiểu 8 ký tự.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Mật khẩu phải chứa ít nhất 1 chữ cái viết hoa.")
    if not re.search(r"[a-z]", password):
        raise ValueError("Mật khẩu phải chứa ít nhất 1 chữ cái viết thường.")
    if not re.search(r"\d", password):
        raise ValueError("Mật khẩu phải chứa ít nhất 1 chữ số.")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        raise ValueError("Mật khẩu phải chứa ít nhất 1 ký tự đặc biệt (!@#$%...).")
    return password

def create_jwt_tokens(email: str):
    """Sinh Access Token & Refresh Token bằng RSA Private Key (RS256)."""
    now = datetime.now(timezone.utc)
    
    access_payload = {
        "sub": email,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=15)
    }
    
    refresh_payload = {
        "sub": email,
        "type": "refresh",
        "iat": now,
        "exp": now + timedelta(days=7)
    }

    access_token = jwt.encode(access_payload, PEM_PRIVATE_KEY, algorithm="RS256")
    refresh_token = jwt.encode(refresh_payload, PEM_PRIVATE_KEY, algorithm="RS256")
    
    return access_token, refresh_token

def decode_jwt_token(token: str):
    """Giải mã & Xác thực JWT Token bằng RSA Public Key (RS256)."""
    try:
        payload = jwt.decode(token, PEM_PUBLIC_KEY, algorithms=["RS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token đã hết hạn.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token không hợp lệ.")

# ==========================================
# 3. PYDANTIC MODELS (INPUT SANITIZATION)
# ==========================================

class RegisterModel(BaseModel):
    fullname: str
    email: EmailStr
    password: str

    @field_validator('fullname', mode='before')
    def sanitize_fullname(cls, v):
        if isinstance(v, str):
            return html.escape(v.strip())
        return v

    @field_validator('password')
    def check_password(cls, v):
        return validate_password_complexity(v)

class LoginModel(BaseModel):
    email: EmailStr
    password: str

class ForgotPasswordModel(BaseModel):
    email: EmailStr

class ResetPasswordModel(BaseModel):
    reset_token: str
    new_password: str

    @field_validator('new_password')
    def check_new_password(cls, v):
        return validate_password_complexity(v)

class RefreshTokenModel(BaseModel):
    refresh_token: str

# ==========================================
# 4. API ENDPOINTS
# ==========================================

@app.post("/api/auth/register", status_code=201)
async def register(data: RegisterModel):
    """Đăng ký tài khoản & Kiểm tra dữ liệu đầu vào."""
    if data.email in users_db:
        raise HTTPException(status_code=400, detail="Email này đã được đăng ký.")
    
    hashed_pwd = hash_password_with_pepper(data.password)
    users_db[data.email] = {
        "fullname": data.fullname,
        "email": data.email,
        "password": hashed_pwd,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    return {
        "message": "Đăng ký tài khoản thành công!",
        "user": {"fullname": data.fullname, "email": data.email}
    }

@app.post("/api/auth/login")
async def login(data: LoginModel):
    """Đăng nhập cơ bản & Sinh mã JWT."""
    user = users_db.get(data.email)
    if not user or not verify_password_with_pepper(user["password"], data.password):
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không chính xác.")
    
    access_token, refresh_token = create_jwt_tokens(data.email)
    return {
        "message": "Đăng nhập thành công!",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/api/auth/refresh")
async def refresh_tokens(data: RefreshTokenModel):
    """Sinh Access Token mới từ Refresh Token."""
    payload = decode_jwt_token(data.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Token không phải là Refresh Token.")
    
    email = payload.get("sub")
    if email not in users_db:
        raise HTTPException(status_code=404, detail="Người dùng không tồn tại.")
        
    access_token, new_refresh_token = create_jwt_tokens(email)
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

@app.post("/api/auth/forgot-password")
async def forgot_password(data: ForgotPasswordModel):
    """Tạo Reset Token có thời gian hết hạn (15 phút)."""
    if data.email not in users_db:
        # Nhằm bảo mật, không tiết lộ email có tồn tại hay không
        return {"message": "Nếu email tồn tại, một mã Reset Token đã được gửi."}
    
    token = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    reset_tokens_db[token] = {
        "email": data.email,
        "expires_at": expires_at
    }
    
    return {
        "message": "Yêu cầu Reset Token thành công!",
        "reset_token": token,
        "expires_in": "15 phút"
    }

@app.post("/api/auth/reset-password")
async def reset_password(data: ResetPasswordModel):
    """Đặt lại mật khẩu mới bằng Reset Token."""
    token_info = reset_tokens_db.get(data.reset_token)
    if not token_info:
        raise HTTPException(status_code=400, detail="Reset Token không hợp lệ hoặc không tồn tại.")
    
    if datetime.now(timezone.utc) > token_info["expires_at"]:
        del reset_tokens_db[data.reset_token]
        raise HTTPException(status_code=400, detail="Reset Token đã hết hạn.")
    
    email = token_info["email"]
    users_db[email]["password"] = hash_password_with_pepper(data.new_password)
    
    # Hủy token sau khi đã sử dụng
    del reset_tokens_db[data.reset_token]
    
    return {"message": "Đặt lại mật khẩu thành công! Bạn có thể đăng nhập ngay."}

@app.get("/api/auth/rsa-public-key")
async def get_public_key():
    """Lấy RSA Public Key dùng để kiểm tra mã JWT phía Client."""
    return {"public_key": PEM_PUBLIC_KEY.decode("utf-8")}

@app.get("/", response_class=FileResponse)
async def read_index():
    return FileResponse("index.html")
