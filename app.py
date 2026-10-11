import os
import httpx
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Đảm bảo bạn đang import đúng tên file (auth.py hoặc auth_core.py)
from auth import login, AuthError 

app = FastAPI()

# ---------------------------------------------------------
# TẦNG 1: RATE LIMITING
# ---------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------
# TẤM CHẮN BẢO VỆ: HTTP SECURITY HEADERS (NATIVE)
# ---------------------------------------------------------
@app.middleware("http")
async def set_secure_headers(request: Request, call_next):
    response = await call_next(request)
    # Áp dụng các Header bảo mật chuẩn
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Cấu hình CSP cho phép Cloudflare Turnstile CAPTCHA# Cấu hình CSP cho phép Cloudflare Turnstile CAPTCHA và giao diện Swagger UI
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:; frame-src 'self' https://challenges.cloudflare.com"
    return response

# ---------------------------------------------------------
# CƠ CHẾ KIỂM TRA CAPTCHA
# ---------------------------------------------------------
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET_KEY", "your_secret_key_here")

async def verify_turnstile(token: str, ip: str) -> bool:
    if not token:
        return False
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data={"secret": TURNSTILE_SECRET, "response": token, "remoteip": ip},
                timeout=5.0
            )
            return resp.json().get("success", False)
        except Exception:
            return False

class LoginRequest(BaseModel):
    username_or_email: str
    password: str
    captcha_token: str

@app.post("/api/auth/login")
@limiter.limit("5/minute")
async def api_login(request: Request, body: LoginRequest):
   is_human = await verify_turnstile(body.captcha_token, request.client.host)
    if not is_human:
        raise HTTPException(status_code=403, detail="Xác thực CAPTCHA thất bại")
    
    try:
        result = login(body.username_or_email, body.password)
        return {"success": True, "data": result}
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))