"""
Core Auth & Cryptography module (Thành viên 1)
- Đăng ký + Input Sanitization
- Đăng nhập cơ bản
- Argon2id + Salt động (tự sinh trong hash) + Pepper tĩnh (từ biến môi trường)
- JWT Access/Refresh Token ký bằng ECDSA (ES256), quản lý cặp khóa
- Quên mật khẩu: Reset Token có thời hạn, dùng một lần, chỉ lưu hash

Cài: python -m pip install argon2-cffi PyJWT cryptography
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
import unicodedata
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# ---------------------------------------------------------------- cấu hình
DB_PATH = os.environ.get("AUTH_DB", "auth.db")
KEY_DIR = Path(os.environ.get("AUTH_KEY_DIR", "keys"))
ACCESS_TTL = 15 * 60               # 15 phút
REFRESH_TTL = 7 * 24 * 3600        # 7 ngày
RESET_TTL = 15 * 60                # 15 phút
MAX_FAILED = 5                     # khóa tạm sau 5 lần sai
LOCK_SECONDS = 5 * 60
ISSUER = "secure-login-app"

_ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)


class AuthError(Exception):
    pass


# ---------------------------------------------------------------- pepper
def _load_pepper() -> bytes:
    """Pepper tĩnh: ưu tiên biến môi trường AUTH_PEPPER, nếu không có thì
    sinh 1 lần và lưu thành file riêng (tách khỏi DB)."""
    env = os.environ.get("AUTH_PEPPER")
    if env:
        return env.encode()
    KEY_DIR.mkdir(exist_ok=True)
    p = KEY_DIR / "pepper.key"
    if not p.exists():
        p.write_text(secrets.token_hex(32))
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    return p.read_text().encode()


PEPPER = _load_pepper()


# ---------------------------------------------------------------- sanitization
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.]{3,32}$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def sanitize_username(u: str) -> str:
    u = unicodedata.normalize("NFKC", (u or "").strip())
    if not _USERNAME_RE.fullmatch(u):
        raise AuthError("Username 3-32 ký tự, chỉ gồm chữ, số, '_' hoặc '.'")
    return u.lower()


def sanitize_email(e: str) -> str:
    e = unicodedata.normalize("NFKC", (e or "").strip()).lower()
    if len(e) > 254 or not _EMAIL_RE.fullmatch(e):
        raise AuthError("Email không hợp lệ")
    return e


def validate_password_policy(p: str, username: str = "") -> None:
    errs = []
    if not (12 <= len(p) <= 128):
        errs.append("độ dài 12-128 ký tự")
    if not re.search(r"[A-Z]", p):
        errs.append("có chữ hoa")
    if not re.search(r"[a-z]", p):
        errs.append("có chữ thường")
    if not re.search(r"\d", p):
        errs.append("có chữ số")
    if not re.search(r"[^A-Za-z0-9]", p):
        errs.append("có ký tự đặc biệt")
    if username and username.lower() in p.lower():
        errs.append("không chứa username")
    if errs:
        raise AuthError("Mật khẩu cần: " + ", ".join(errs))


# ---------------------------------------------------------------- băm mật khẩu
def _pepper_input(password: str) -> str:
    """HMAC-SHA256(pepper, password) -> hex."""
    return hmac.new(PEPPER, password.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_password(password: str) -> str:
    # Argon2id tự sinh salt ngẫu nhiên 16 byte cho mỗi lần hash (salt động)
    return _ph.hash(_pepper_input(password))


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, _pepper_input(password))
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _ph.check_needs_rehash(stored_hash)


# ---------------------------------------------------------------- quản lý khóa ECDSA
def _load_or_create_keys():
    KEY_DIR.mkdir(exist_ok=True)
    priv_p, pub_p = KEY_DIR / "jwt_private.pem", KEY_DIR / "jwt_public.pem"
    if not priv_p.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        priv_p.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        pub_p.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        try:
            os.chmod(priv_p, 0o600)
        except OSError:
            pass
    return priv_p.read_bytes(), pub_p.read_bytes()


_PRIV, _PUB = _load_or_create_keys()


# ---------------------------------------------------------------- DB
def _db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def init_db():
    with _db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until REAL NOT NULL DEFAULT 0,
            created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS refresh_tokens(
            jti TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at REAL NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS reset_tokens(
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at REAL NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );
        """)


# ---------------------------------------------------------------- JWT
def _make_token(user_id: int, kind: str, ttl: int) -> tuple[str, str]:
    now = int(time.time())
    jti = secrets.token_hex(16)
    payload = {"iss": ISSUER, "sub": str(user_id), "type": kind,
               "iat": now, "exp": now + ttl, "jti": jti}
    return jwt.encode(payload, _PRIV, algorithm="ES256"), jti


def verify_token(token: str, expected_type: str) -> dict:
    try:
        data = jwt.decode(token, _PUB, algorithms=["ES256"], issuer=ISSUER,
                          options={"require": ["exp", "iat", "sub", "jti"]})
    except jwt.ExpiredSignatureError:
        raise AuthError("Token đã hết hạn")
    except jwt.PyJWTError:
        raise AuthError("Token không hợp lệ")
    if data.get("type") != expected_type:
        raise AuthError("Sai loại token")
    return data


def _issue_pair(con, user_id: int) -> dict:
    access, _ = _make_token(user_id, "access", ACCESS_TTL)
    refresh_t, jti = _make_token(user_id, "refresh", REFRESH_TTL)
    con.execute("INSERT INTO refresh_tokens(jti,user_id,expires_at) VALUES(?,?,?)",
                (jti, user_id, time.time() + REFRESH_TTL))
    return {"access_token": access, "refresh_token": refresh_t}


# ---------------------------------------------------------------- API chính
def register(username: str, email: str, password: str) -> int:
    username = sanitize_username(username)
    email = sanitize_email(email)
    validate_password_policy(password, username)
    pw_hash = hash_password(password)
    try:
        with _db() as c:
            cur = c.execute(
                "INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)",
                (username, email, pw_hash, time.time()))
            return cur.lastrowid
    except sqlite3.IntegrityError:
        raise AuthError("Username hoặc email đã tồn tại")


# hash giả để thời gian phản hồi không lộ việc user có tồn tại hay không
_DUMMY_HASH = hash_password("dummy-Password-123!")


def login(username_or_email: str, password: str) -> dict:
    ident = (username_or_email or "").strip().lower()
    generic = AuthError("Sai tên đăng nhập hoặc mật khẩu")
    with _db() as c:
        u = c.execute("SELECT * FROM users WHERE username=? OR email=?",
                      (ident, ident)).fetchone()
        if not u:
            verify_password(_DUMMY_HASH, password)
            raise generic
        if u["locked_until"] > time.time():
            raise AuthError("Tài khoản bị khóa tạm thời, thử lại sau")
        if not verify_password(u["password_hash"], password):
            fails = u["failed_attempts"] + 1
            locked = time.time() + LOCK_SECONDS if fails >= MAX_FAILED else 0
            c.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                      (0 if locked else fails, locked, u["id"]))
            c.commit()  # phải commit trước khi raise, nếu không sẽ bị rollback
            raise generic
        c.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?", (u["id"],))
        if needs_rehash(u["password_hash"]):
            c.execute("UPDATE users SET password_hash=? WHERE id=?",
                      (hash_password(password), u["id"]))
        pair = _issue_pair(c, u["id"])
        pair["user"] = {"id": u["id"], "username": u["username"], "email": u["email"]}
        return pair


def refresh(refresh_token: str) -> dict:
    data = verify_token(refresh_token, "refresh")
    with _db() as c:
        row = c.execute("SELECT * FROM refresh_tokens WHERE jti=?", (data["jti"],)).fetchone()
        if not row or row["revoked"]:
            # token đã dùng/thu hồi -> nghi bị đánh cắp: thu hồi toàn bộ phiên
            c.execute("UPDATE refresh_tokens SET revoked=1 WHERE user_id=?", (int(data["sub"]),))
            c.commit()
            raise AuthError("Refresh token không hợp lệ")
        c.execute("UPDATE refresh_tokens SET revoked=1 WHERE jti=?", (data["jti"],))  # rotation
        return _issue_pair(c, int(data["sub"]))


def logout(refresh_token: str) -> None:
    data = verify_token(refresh_token, "refresh")
    with _db() as c:
        c.execute("UPDATE refresh_tokens SET revoked=1 WHERE jti=?", (data["jti"],))


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def request_password_reset(email: str) -> str | None:
    """Trả về token thô (app thật: gửi qua email, KHÔNG trả cho client).
    Email không tồn tại -> None."""
    try:
        email = sanitize_email(email)
    except AuthError:
        return None
    with _db() as c:
        u = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not u:
            return None
        c.execute("UPDATE reset_tokens SET used=1 WHERE user_id=? AND used=0", (u["id"],))
        raw = secrets.token_urlsafe(32)
        c.execute("INSERT INTO reset_tokens(token_hash,user_id,expires_at) VALUES(?,?,?)",
                  (_sha256(raw), u["id"], time.time() + RESET_TTL))
        return raw


def reset_password(raw_token: str, new_password: str) -> None:
    with _db() as c:
        row = c.execute("SELECT * FROM reset_tokens WHERE token_hash=?",
                        (_sha256(raw_token or ""),)).fetchone()
        if not row or row["used"] or row["expires_at"] < time.time():
            raise AuthError("Reset token không hợp lệ hoặc đã hết hạn")
        uname = c.execute("SELECT username FROM users WHERE id=?", (row["user_id"],)).fetchone()[0]
        validate_password_policy(new_password, uname)
        c.execute("UPDATE users SET password_hash=?, failed_attempts=0, locked_until=0 WHERE id=?",
                  (hash_password(new_password), row["user_id"]))
        c.execute("UPDATE reset_tokens SET used=1 WHERE token_hash=?", (row["token_hash"],))
        c.execute("UPDATE refresh_tokens SET revoked=1 WHERE user_id=?", (row["user_id"],))


init_db()

# ---------------------------------------------------------------- demo
if __name__ == "__main__":
    print("== Demo ==")
    uid = register("Cat_Dev", "cat@example.com", "MatKhau#Manh2026!")
    print("Đăng ký OK, id =", uid)
    tokens = login("cat_dev", "MatKhau#Manh2026!")
    print("Đăng nhập OK, sub =", verify_token(tokens["access_token"], "access")["sub"])
    refresh(tokens["refresh_token"])
    print("Refresh OK (rotation)")
    try:
        refresh(tokens["refresh_token"])
    except AuthError as e:
        print("Dùng lại refresh cũ -> chặn:", e)
    t = request_password_reset("cat@example.com")
    reset_password(t, "MatKhauMoi#2026xyz")
    print("Reset password OK")
    try:
        reset_password(t, "KhacNua#2026abcd")
    except AuthError as e:
        print("Dùng lại reset token -> chặn:", e)
    for _ in range(5):
        try:
            login("cat_dev", "sai")
        except AuthError:
            pass
    try:
        login("cat_dev", "MatKhauMoi#2026xyz")
    except AuthError as e:
        print("Khóa tạm:", e)
    try:
        register("x", "bad", "123")
    except AuthError as e:
        print("Sanitize:", e)