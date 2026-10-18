import re
import html
import uuid
import io
import base64
import random
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List

from fastapi import FastAPI, HTTPException, status, Depends, Header
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr, field_validator
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

import jwt
import pyotp
import qrcode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ==========================================
# 1. CẤU HÌNH BẢO MẬT & MÃ HÓA
# ==========================================

PEPPER = "StaticPepperSecret_2026_SecurePepperKey!@#"
ph = PasswordHasher()

# Cặp khóa RSA 2048-bit ký JWT
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

# Database In-memory
users_db: Dict[str, dict] = {}
reset_tokens_db: Dict[str, dict] = {}
email_otps_db: Dict[str, dict] = {}

def hash_password_with_pepper(password: str) -> str:
    return ph.hash(password + PEPPER)

def verify_password_with_pepper(hash_str: str, password: str) -> bool:
    try:
        return ph.verify(hash_str, password + PEPPER)
    except (VerifyMismatchError, VerificationError):
        return False

# Khởi tạo dữ liệu sẵn để không bị mất khi reload
users_db["admin@test.com"] = {
    "fullname": "Admin User",
    "email": "admin@test.com",
    "password": hash_password_with_pepper("P@ssword2026!"),
    "role": "Admin",
    "totp_secret": None,
    "totp_enabled": False,
    "email_otp_enabled": False,
    "backup_codes": [],
    "created_at": datetime.now(timezone.utc).isoformat()
}

app = FastAPI(title="Core Auth, MFA & RBAC System")

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================

def validate_password_complexity(password: str):
    if len(password) < 8:
        raise ValueError("Mật khẩu phải có độ dài tối thiểu 8 ký tự.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Mật khẩu phải chứa ít nhất 1 chữ cái viết hoa.")
    if not re.search(r"[a-z]", password):
        raise ValueError("Mật khẩu phải chứa ít nhất 1 chữ cái viết thường.")
    if not re.search(r"\d", password):
        raise ValueError("Mật khẩu phải chứa ít nhất 1 chữ số.")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        raise ValueError("Mật khẩu phải chứa ít nhất 1 ký tự đặc biệt.")
    return password

def create_jwt_tokens(email: str, is_partial: bool = False, role: str = "User"):
    now = datetime.now(timezone.utc)
    access_payload = {
        "sub": email,
        "role": role,
        "type": "access",
        "partial": is_partial,
        "iat": now,
        "exp": now + timedelta(minutes=15)
    }
    refresh_payload = {
        "sub": email,
        "role": role,
        "type": "refresh",
        "partial": is_partial,
        "iat": now,
        "exp": now + timedelta(days=7)
    }

    access_token = jwt.encode(access_payload, PEM_PRIVATE_KEY, algorithm="RS256")
    refresh_token = jwt.encode(refresh_payload, PEM_PRIVATE_KEY, algorithm="RS256")
    return access_token, refresh_token

def decode_jwt_token(token: str):
    try:
        return jwt.decode(token, PEM_PUBLIC_KEY, algorithms=["RS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token đã hết hạn.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token không hợp lệ.")

def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Thiếu Token xác thực (Bearer).")
    token = authorization.split(" ")[1]
    payload = decode_jwt_token(token)
    
    email = payload.get("sub")
    if not email or email not in users_db:
        raise HTTPException(status_code=401, detail="Tài khoản không tồn tại hoặc đã bị xóa.")

    if payload.get("partial") is True:
        raise HTTPException(status_code=403, detail="Yêu cầu hoàn tất xác thực 2FA trước (Partial Auth).")
        
    return payload

def require_role(allowed_roles: List[str]):
    def role_checker(user: dict = Depends(get_current_user)):
        if user.get("role") not in allowed_roles:
            raise HTTPException(status_code=403, detail=f"Không đủ quyền hạn! Yêu cầu vai trò: {', '.join(allowed_roles)}")
        return user
    return role_checker

# ==========================================
# 3. MODELS
# ==========================================

class RegisterModel(BaseModel):
    fullname: str
    email: EmailStr
    password: str
    role: Optional[str] = "User"

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

class VerifyMFAChallengeModel(BaseModel):
    email: EmailStr
    partial_token: str
    method: str
    code: str

class Toggle2FAModel(BaseModel):
    method: str
    enable: bool

class OAuthLoginModel(BaseModel):
    provider: str
    oauth_token: str

# ==========================================
# 4. API ENDPOINTS
# ==========================================

@app.post("/api/auth/register", status_code=201)
async def register(data: RegisterModel):
    if data.email in users_db:
        raise HTTPException(status_code=400, detail="Email này đã được đăng ký.")
    
    role = data.role if data.role in ["User", "Auditor", "Admin"] else "User"
    
    users_db[data.email] = {
        "fullname": data.fullname,
        "email": data.email,
        "password": hash_password_with_pepper(data.password),
        "role": role,
        "totp_secret": None,
        "totp_enabled": False,
        "email_otp_enabled": False,
        "backup_codes": [],
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    return {
        "message": "Đăng ký tài khoản thành công!",
        "user": {"fullname": data.fullname, "email": data.email, "role": role}
    }

@app.post("/api/auth/login")
async def login(data: LoginModel):
    user = users_db.get(data.email)
    if not user or not verify_password_with_pepper(user["password"], data.password):
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không chính xác.")
    
    mfa_required = user["totp_enabled"] or user["email_otp_enabled"]
    
    access_token, refresh_token = create_jwt_tokens(
        email=data.email, 
        is_partial=mfa_required, 
        role=user["role"]
    )
    
    sent_otp = None
    if user["email_otp_enabled"]:
        otp_code = f"{random.randint(100000, 999999)}"
        email_otps_db[data.email] = {
            "code": otp_code,
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)
        }
        sent_otp = otp_code
    
    return {
        "message": "Cần xác thực 2FA!" if mfa_required else "Đăng nhập thành công!",
        "mfa_required": mfa_required,
        "mfa_methods": {
            "totp": user["totp_enabled"],
            "email_otp": user["email_otp_enabled"]
        },
        "email_otp_debug": sent_otp,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/api/mfa/challenge")
async def mfa_challenge(data: VerifyMFAChallengeModel):
    payload = decode_jwt_token(data.partial_token)
    if payload.get("sub") != data.email:
        raise HTTPException(status_code=400, detail="Token và Email không khớp.")
    
    user = users_db.get(data.email)
    if not user:
        raise HTTPException(status_code=404, detail="Người dùng không tồn tại.")

    verified = False

    if data.method == "totp":
        if not user["totp_enabled"] or not user["totp_secret"]:
            raise HTTPException(status_code=400, detail="TOTP chưa được bật cho tài khoản này.")
        totp = pyotp.TOTP(user["totp_secret"])
        verified = totp.verify(data.code)

    elif data.method == "backup":
        if data.code in user["backup_codes"]:
            verified = True
            user["backup_codes"].remove(data.code)

    elif data.method == "email_otp":
        otp_info = email_otps_db.get(data.email)
        if otp_info and otp_info["code"] == data.code:
            if datetime.now(timezone.utc) <= otp_info["expires_at"]:
                verified = True
                del email_otps_db[data.email]

    if not verified:
        raise HTTPException(status_code=400, detail="Mã xác thực 2FA không hợp lệ hoặc đã hết hạn.")

    full_access_token, full_refresh_token = create_jwt_tokens(
        email=data.email, 
        is_partial=False, 
        role=user["role"]
    )

    return {
        "message": "Xác thực 2FA thành công! Đã chuyển sang Full Auth.",
        "access_token": full_access_token,
        "refresh_token": full_refresh_token,
        "token_type": "bearer"
    }

@app.post("/api/mfa/totp/setup")
async def setup_totp(user_payload: dict = Depends(get_current_user)):
    email = user_payload["sub"]
    user = users_db[email]

    secret = pyotp.random_base32()
    user["totp_secret"] = secret
    
    backup_codes = [str(uuid.uuid4())[:8] for _ in range(5)]
    user["backup_codes"] = backup_codes

    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email, 
        issuer_name="CoreAuthMFAApp"
    )

    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return {
        "secret": secret,
        "qr_code_base64": f"data:image/png;base64,{qr_base64}",
        "backup_codes": backup_codes
    }

@app.post("/api/mfa/toggle")
async def toggle_mfa(data: Toggle2FAModel, user_payload: dict = Depends(get_current_user)):
    email = user_payload["sub"]
    user = users_db[email]

    if data.method == "totp":
        if data.enable and not user["totp_secret"]:
            raise HTTPException(status_code=400, detail="Cần thiết lập TOTP Secret trước khi bật.")
        user["totp_enabled"] = data.enable
    elif data.method == "email_otp":
        user["email_otp_enabled"] = data.enable

    return {
        "message": f"Đã {'kích hoạt' if data.enable else 'thu hồi'} 2FA ({data.method.upper()}) thành công!",
        "mfa_status": {
            "totp": user["totp_enabled"],
            "email_otp": user["email_otp_enabled"]
        }
    }

@app.post("/api/auth/oauth/login")
async def oauth_login(data: OAuthLoginModel):
    fake_email = f"user_{data.provider}@oauth.com"
    
    if fake_email not in users_db:
        users_db[fake_email] = {
            "fullname": f"OAuth {data.provider.capitalize()} User",
            "email": fake_email,
            "password": hash_password_with_pepper(str(uuid.uuid4())),
            "role": "User",
            "totp_secret": None,
            "totp_enabled": False,
            "email_otp_enabled": False,
            "backup_codes": [],
            "created_at": datetime.now(timezone.utc).isoformat()
        }

    access_token, refresh_token = create_jwt_tokens(fake_email, is_partial=False, role="User")
    return {
        "message": f"Đăng nhập thành công via {data.provider.capitalize()}!",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.get("/api/rbac/user-area")
async def user_area(user: dict = Depends(require_role(["User", "Auditor", "Admin"]))):
    return {"message": "Chào mừng đến với Khu vực Người dùng!", "user": user}

@app.get("/api/rbac/auditor-area")
async def auditor_area(user: dict = Depends(require_role(["Auditor", "Admin"]))):
    return {"message": "Báo cáo Kiểm toán Bảo mật (Auditor Area)", "logs": ["LOG_1", "LOG_2"], "user": user}

@app.get("/api/rbac/admin-area")
async def admin_area(user: dict = Depends(require_role(["Admin"]))):
    return {"message": "Bảng Điều Khiển Quản Trị Viên (Admin Area)", "all_users": list(users_db.keys()), "user": user}

@app.post("/api/auth/forgot-password")
async def forgot_password(data: ForgotPasswordModel):
    if data.email not in users_db:
        return {"message": "Nếu email tồn tại, một mã Reset Token đã được gửi."}
    
    token = str(uuid.uuid4())
    reset_tokens_db[token] = {
        "email": data.email,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=15)
    }
    return {"message": "Yêu cầu Reset Token thành công!", "reset_token": token}

@app.post("/api/auth/reset-password")
async def reset_password(data: ResetPasswordModel):
    token_info = reset_tokens_db.get(data.reset_token)
    if not token_info or datetime.now(timezone.utc) > token_info["expires_at"]:
        raise HTTPException(status_code=400, detail="Token không hợp lệ hoặc đã hết hạn.")
    
    users_db[token_info["email"]]["password"] = hash_password_with_pepper(data.new_password)
    del reset_tokens_db[data.reset_token]
    return {"message": "Đặt lại mật khẩu thành công!"}

@app.get("/", response_class=FileResponse)
async def read_index():
    return FileResponse("index.html")
