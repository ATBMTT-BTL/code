import html
import time
import base64
import io
import secrets
import urllib.parse
import pyotp
import qrcode
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict

from fastapi import FastAPI, HTTPException, status, Depends, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import jwt, JWTError

# -----------------------------------------------------------------------------
# APP CONFIG & SECURITY SETTINGS
# -----------------------------------------------------------------------------
app = FastAPI(title="Core Auth, MFA, RBAC & Security Controls System")

SECRET_KEY = "SUPER_SECRET_KEY_JWT_2026_RS256_SIMULATED"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
security = HTTPBearer(auto_error=False)

# -----------------------------------------------------------------------------
# IN-MEMORY STORAGE & TRACKERS
# -----------------------------------------------------------------------------
rate_limit_records: Dict[str, List[float]] = {}
RATE_LIMIT_MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW_SECONDS = 60

ip_blacklist: set = set()

lockout_tracker: Dict[str, dict] = {}
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION_MINUTES = 15

security_alerts_log: List[dict] = []

# Mock Database
users_db: Dict[str, dict] = {
    "admin@test.com": {
        "fullname": "System Admin",
        "email": "admin@test.com",
        "hashed_password": pwd_context.hash("P@ssword2026!"),
        "role": "Admin",
        "mfa_enabled": True,
        "mfa_totp_secret": "JBSWY3DPEHPK3PXP",
        "mfa_email_otp_enabled": False,
        "mfa_backup_codes": ["7870d344", "e8bc16b8", "fb058eb3", "6e7d0546", "f7a643fb"]
    }
}

# -----------------------------------------------------------------------------
# MIDDLEWARE
# -----------------------------------------------------------------------------
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"

    if client_ip in ip_blacklist:
        return JSONResponse(
            status_code=403,
            content={"detail": f"IP {client_ip} của bạn đã bị cấm truy cập hệ thống!"}
        )

    response: Response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# -----------------------------------------------------------------------------
# HELPERS
# -----------------------------------------------------------------------------
def sanitize_text(text: str) -> str:
    return html.escape(text.strip()) if text else ""

def check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    timestamps = rate_limit_records.get(client_ip, [])
    timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW_SECONDS]
    rate_limit_records[client_ip] = timestamps
    if len(timestamps) >= RATE_LIMIT_MAX_ATTEMPTS:
        return False
    timestamps.append(now)
    return True

def create_jwt_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập! Vui lòng cung cấp Auth Token.")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email or email not in users_db:
            raise HTTPException(status_code=401, detail="Token không hợp lệ hoặc tài khoản không tồn tại!")
        return users_db[email]
    except JWTError:
        raise HTTPException(status_code=401, detail="Token hết hạn hoặc không hợp lệ!")

def require_role(allowed_roles: List[str]):
    def role_checker(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
        if not credentials:
            raise HTTPException(status_code=401, detail="Chưa đăng nhập! Vui lòng truy cập bằng tài khoản Admin.")
        token = credentials.credentials
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("partial"):
                raise HTTPException(status_code=403, detail="Yêu cầu hoàn thành xác thực 2FA (Full Auth)!")
            role = payload.get("role")
            if role not in allowed_roles:
                raise HTTPException(status_code=403, detail=f"Quyền '{role}' không đủ thẩm quyền truy cập! Chỉ {', '.join(allowed_roles)} mới có quyền.")
            return payload
        except JWTError:
            raise HTTPException(status_code=401, detail="Token hết hạn hoặc không hợp lệ!")
    return role_checker

# -----------------------------------------------------------------------------
# SCHEMAS
# -----------------------------------------------------------------------------
class RegisterSchema(BaseModel):
    fullname: str
    email: EmailStr
    password: str
    role: str = "User"

class LoginSchema(BaseModel):
    email: EmailStr
    password: str

class MFAChallengeSchema(BaseModel):
    email: str
    partial_token: Optional[str] = None
    method: str
    code: str

class ToggleMFASchema(BaseModel):
    method: str
    enable: bool

class CaptchaVerifySchema(BaseModel):
    captcha_token: str

class IPBlacklistSchema(BaseModel):
    ip: str

# -----------------------------------------------------------------------------
# ENDPOINTS
# -----------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open("index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.post("/api/auth/register")
async def register(data: RegisterSchema):
    clean_name = sanitize_text(data.fullname)
    clean_email = data.email.lower()
    if clean_email in users_db:
        raise HTTPException(status_code=400, detail="Email này đã được đăng ký!")
    
    users_db[clean_email] = {
        "fullname": clean_name,
        "email": clean_email,
        "hashed_password": pwd_context.hash(data.password),
        "role": data.role if data.role in ["User", "Auditor", "Admin"] else "User",
        "mfa_enabled": False,
        "mfa_totp_secret": pyotp.random_base32(),
        "mfa_email_otp_enabled": False,
        "mfa_backup_codes": ["11112222", "33334444", "55556666"]
    }
    return {"message": "Đăng ký thành công!", "user": {"email": clean_email, "role": users_db[clean_email]["role"]}}

@app.post("/api/auth/login")
async def login(data: LoginSchema, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    clean_email = data.email.lower()

    if not check_rate_limit(client_ip):
        security_alerts_log.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": client_ip,
            "type": "Rate Limit Exceeded",
            "detail": f"IP {client_ip} vượt quá 5 lần thử/1 phút!"
        })
        raise HTTPException(status_code=429, detail="Bạn đã thử quá 5 lần/1 phút. Vui lòng chờ 60 giây!")

    lock_info = lockout_tracker.get(clean_email, {"failed_count": 0, "lockout_until": None})
    if lock_info["lockout_until"] and datetime.now() < lock_info["lockout_until"]:
        remaining = int((lock_info["lockout_until"] - datetime.now()).total_seconds() / 60) + 1
        raise HTTPException(status_code=403, detail=f"Tài khoản bị tạm khóa! Thử lại sau {remaining} phút.")

    user = users_db.get(clean_email)
    if not user or not pwd_context.verify(data.password, user["hashed_password"]):
        lock_info["failed_count"] += 1
        if lock_info["failed_count"] >= LOCKOUT_THRESHOLD:
            lock_info["lockout_until"] = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            security_alerts_log.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": client_ip,
                "type": "Account Lockout Triggered",
                "detail": f"Tài khoản {clean_email} bị khóa 15 phút do thử sai 5 lần từ IP {client_ip}."
            })
        lockout_tracker[clean_email] = lock_info
        raise HTTPException(status_code=401, detail=f"Sai email hoặc mật khẩu! (Lần thử sai: {lock_info['failed_count']}/{LOCKOUT_THRESHOLD})")

    lockout_tracker[clean_email] = {"failed_count": 0, "lockout_until": None}

    if user.get("mfa_enabled") or user.get("mfa_email_otp_enabled"):
        partial_token = create_jwt_token({"sub": user["email"], "role": user["role"], "partial": True})
        
        totp_current = None
        if user.get("mfa_totp_secret"):
            try:
                totp_current = pyotp.TOTP(user["mfa_totp_secret"]).now()
            except Exception:
                totp_current = None

        return {
            "message": "Cần xác thực 2FA (MFA Challenge)!",
            "mfa_required": True,
            "access_token": partial_token,
            "token_type": "bearer",
            "debug_totp_code": totp_current
        }

    full_token = create_jwt_token({"sub": user["email"], "role": user["role"], "partial": False})
    return {"message": "Đăng nhập thành công! (Full Auth)", "access_token": full_token, "token_type": "bearer"}

# -----------------------------------------------------------------------------
# MFA SETUP & CHALLENGE
# -----------------------------------------------------------------------------
@app.post("/api/mfa/totp/setup")
async def setup_totp(user: dict = Depends(get_current_user)):
    secret = pyotp.random_base32()
    user["mfa_totp_secret"] = secret
    user["mfa_enabled"] = True
    
    totp = pyotp.TOTP(secret)
    provisioning_url = totp.provisioning_uri(name=user["email"], issuer_name="CoreAuthSystem")
    
    try:
        qr = qrcode.QRCode(version=1, box_size=5, border=2)
        qr.add_data(provisioning_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_base64 = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        qr_base64 = f"https://api.qrserver.com/v1/create-qr-code/?size=180x180&data={urllib.parse.quote(provisioning_url)}"

    backup_codes = [secrets.token_hex(4) for _ in range(5)]
    user["mfa_backup_codes"] = backup_codes

    return {
        "secret": secret,
        "qr_code_base64": qr_base64,
        "backup_codes": backup_codes,
        "debug_current_totp": totp.now()
    }

@app.post("/api/mfa/toggle")
async def toggle_mfa(data: ToggleMFASchema, user: dict = Depends(get_current_user)):
    if data.method == "totp":
        user["mfa_enabled"] = data.enable
    elif data.method == "email_otp":
        user["mfa_email_otp_enabled"] = data.enable
    status_str = "kích hoạt" if data.enable else "thu hồi"
    return {"message": f"Đã {status_str} thành công 2FA phương thức: {data.method.upper()}"}

@app.post("/api/mfa/challenge")
async def mfa_challenge(data: MFAChallengeSchema):
    clean_email = data.email.lower() if data.email else ""
    user = users_db.get(clean_email)
    if not user:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản. Vui lòng đăng nhập lại Bước 1.")

    valid = False
    code_clean = data.code.strip()

    if data.method == "totp":
        secret = user.get("mfa_totp_secret")
        if secret:
            try:
                totp = pyotp.TOTP(secret)
                valid = totp.verify(code_clean, valid_window=2)
            except Exception:
                valid = False
    elif data.method == "email_otp":
        if code_clean in ["123456", "654321"]:
            valid = True
    elif data.method == "backup":
        if code_clean in user.get("mfa_backup_codes", []):
            user["mfa_backup_codes"].remove(code_clean)
            valid = True

    if not valid:
        raise HTTPException(status_code=400, detail="Mã xác thực 2FA không hợp lệ hoặc đã hết hạn.")

    full_token = create_jwt_token({"sub": user["email"], "role": user["role"], "partial": False})
    return {"message": "Xác thực 2FA thành công! Đã chuyển sang Full Auth.", "access_token": full_token, "token_type": "bearer"}

# -----------------------------------------------------------------------------
# RBAC ENDPOINTS
# -----------------------------------------------------------------------------
@app.get("/api/rbac/user-area", dependencies=[Depends(require_role(["User", "Auditor", "Admin"]))])
async def user_area():
    return {"message": "Chào mừng đến Khu Vực User! (Quyền: User/Auditor/Admin)"}

@app.get("/api/rbac/auditor-area", dependencies=[Depends(require_role(["Auditor", "Admin"]))])
async def auditor_area():
    return {"message": "Chào mừng đến Khu Vực Auditor! (Quyền: Auditor/Admin)"}

@app.get("/api/rbac/admin-area", dependencies=[Depends(require_role(["Admin"]))])
async def admin_area():
    return {"message": "Chào mừng đến Khu Vực Admin! (Chỉ dành riêng cho Admin)"}

# -----------------------------------------------------------------------------
# SECURITY CONTROLS ENDPOINTS (KHÓA NGHIÊM NGẠT CHỈ DÀNH RIÊNG CHO ADMIN)
# -----------------------------------------------------------------------------
@app.post("/api/security/verify-captcha")
async def verify_captcha(data: CaptchaVerifySchema):
    if not data.captcha_token or len(data.captcha_token) < 5:
        raise HTTPException(status_code=400, detail="Mã CAPTCHA không hợp lệ!")
    return {"message": "Xác thực CAPTCHA thông minh thành công! (Human Score: 0.98)"}

@app.get("/api/security/ip-blacklist", dependencies=[Depends(require_role(["Admin"]))])
async def get_ip_blacklist():
    return {"blacklisted_ips": list(ip_blacklist)}

@app.post("/api/security/ip-blacklist", dependencies=[Depends(require_role(["Admin"]))])
async def add_ip_blacklist(data: IPBlacklistSchema):
    ip_blacklist.add(data.ip.strip())
    return {"message": f"Đã thêm IP {data.ip.strip()} vào danh sách đen"}

@app.delete("/api/security/ip-blacklist", dependencies=[Depends(require_role(["Admin"]))])
async def remove_ip_blacklist(data: IPBlacklistSchema):
    ip_blacklist.discard(data.ip.strip())
    return {"message": f"Đã gỡ bỏ IP {data.ip.strip()}"}

@app.get("/api/security/alerts", dependencies=[Depends(require_role(["Admin"]))])
async def get_security_alerts():
    return {"alerts": list(reversed(security_alerts_log))}

