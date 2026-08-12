import os, io, json, time, secrets, sqlite3, hmac, struct, hashlib, logging, base64, functools
from datetime import datetime
from urllib.parse import urlencode

from flask import request, session, current_app
from flask_login import current_user, UserMixin
from werkzeug.utils import secure_filename
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from PIL import Image

# Paths (env-aware, mirrors __init__.py) 
BASE_DIR   = os.path.abspath(os.path.dirname(__file__))
DB_PATH    = os.path.abspath(os.environ.get("DATABASE_PATH") or os.path.join(BASE_DIR, "secureapp.db"))
UPLOAD_DIR = os.path.abspath(os.environ.get("UPLOAD_DIR") or os.path.join(BASE_DIR, "static", "uploads"))
LOG_PATH   = os.path.abspath(os.environ.get("AUDIT_LOG_FILE") or os.path.join(BASE_DIR, "app.log"))
SCHEMA_PATH = os.path.abspath(os.environ.get("SCHEMA_FILE") or os.path.join(BASE_DIR, "schema.sql"))

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

# DB helpers
def get_db():
    """Open a SQLite connection with FK enforcement and Row mapping."""
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON")
    except Exception:
        pass
    return conn

def db_query(sql, args=(), one=False):
    with get_db() as db:
        cur = db.execute(sql, args)
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows

def db_exec(sql, args=()):
    with get_db() as db:
        cur = db.execute(sql, args)
        db.commit()
        return cur.lastrowid

# Schema / migrations 
def _load_schema_sql() -> str:
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        sql = f.read()
    if not sql.strip():
        raise RuntimeError(f"schema.sql is empty: {SCHEMA_PATH}")
    return sql

def ensure_schema_and_migrations():
    """Create base schema from schema.sql and idempotently add columns used by the app/templates."""
    with get_db() as db:
        db.executescript(_load_schema_sql())

        def has_col(table, col):
            cols = db.execute(f"PRAGMA table_info({table})").fetchall()
            return any(r["name"] == col for r in cols)

        alters = []
        if not has_col("users", "twofa_enabled"):
            alters.append("ALTER TABLE users ADD COLUMN twofa_enabled INTEGER NOT NULL DEFAULT 0;")
        if not has_col("users", "twofa_secret"):
            alters.append("ALTER TABLE users ADD COLUMN twofa_secret TEXT;")
        if not has_col("users", "last_login"):
            alters.append("ALTER TABLE users ADD COLUMN last_login TIMESTAMP;")
        if not has_col("users", "locked_until"):
            alters.append("ALTER TABLE users ADD COLUMN locked_until INTEGER;")
        if not has_col("reviews", "content_html"):
            alters.append("ALTER TABLE reviews ADD COLUMN content_html TEXT;")
        if not has_col("products", "image"):
            alters.append("ALTER TABLE products ADD COLUMN image TEXT;")
        if not has_col("products", "seller_id"):
            alters.append("ALTER TABLE products ADD COLUMN seller_id INTEGER;")

        for stmt in alters:
            try:
                db.execute(stmt)
            except Exception:
                pass
        db.commit()

# Audit helpers
def _ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr) if request else None

def _ua():
    return request.headers.get("User-Agent") if request else None

def log_audit(event_type, route=None, method=None, user_id=None, session_id=None,
              product_id=None, ms=None, ip=None, ua=None, meta=None):
    """Write to audit_events and mirror to app.log."""
    try:
        meta_json = meta
        if isinstance(meta, (dict, list)):
            meta_json = json.dumps(meta, ensure_ascii=False)

        event_id = db_exec(
            """INSERT INTO audit_events
               (ts, event_type, user_id, route, method, product_id, ms, ip, ua, session_id, meta)
               VALUES (CURRENT_TIMESTAMP,?,?,?,?,?,?,?,?,?,?)""",
            (event_type, user_id, route, method, product_id, ms, ip, ua, session_id, meta_json)
        )

        try:
            logger = current_app.logger
        except Exception:
            logger = logging.getLogger("secureapp")
        logger.info(json.dumps({
            "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "event": event_type, "user_id": user_id, "route": route, "method": method,
            "product_id": product_id, "ms": ms, "ip": ip, "ua": ua,
            "session_id": session_id, "meta": meta
        }, ensure_ascii=False))
        return event_id
    except Exception:
        return None

def _audit(event_type, product_id=None, meta=None, started_at=None):
    """Convenience wrapper for views (captures timing and request context)."""
    ms = None
    if started_at is not None:
        ms = int((time.perf_counter() - started_at) * 1000)
    try:
        uid = int(current_user.id) if current_user.is_authenticated else None
    except Exception:
        uid = None
    sid = session.get("_sid")
    if not sid:
        sid = secrets.token_hex(16)
        session["_sid"] = sid
    return log_audit(
        event_type,
        route=(request.path if request else None),
        method=(request.method if request else None),
        user_id=uid, session_id=sid, product_id=product_id,
        ms=ms, ip=_ip(), ua=_ua(), meta=meta
    )

def audit_page(view):
    @functools.wraps(view)
    def wrapper(*a, **k):
        t0 = time.perf_counter()
        resp = view(*a, **k)
        _audit("page_view", started_at=t0)
        return resp
    return wrapper

# Users / security
_ph = PasswordHasher()

class User(UserMixin):
    def __init__(self, row):
        self.id            = row["id"]
        self.username      = row["username"]
        self.email         = row["email"]
        self.password_hash = row["password_hash"]
        self.role          = row["role"]
        rk = row.keys()
        self.twofa_enabled = bool(row["twofa_enabled"]) if "twofa_enabled" in rk else False
        self.twofa_secret  = row["twofa_secret"] if "twofa_secret" in rk else None

    @property
    def is_admin(self):  return self.role == "admin"
    @property
    def is_seller(self): return self.role == "seller"

def get_user_by_email(email):
    return db_query("SELECT * FROM users WHERE email=?", (email,), one=True)

def get_user_by_username(username):
    return db_query("SELECT * FROM users WHERE username=?", (username,), one=True)

def set_last_login(uid):
    db_exec("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?", (uid,))

def _hash_password(plain: str) -> str:
    return _ph.hash(plain)

def _verify_password(stored_hash: str, plain: str) -> bool:
    if not stored_hash:
        return False
    if stored_hash.startswith("$argon2"):
        try:
            return _ph.verify(stored_hash, plain)
        except (VerifyMismatchError, InvalidHash):
            return False
    else:
        try:
            from werkzeug.security import check_password_hash as _wk_check
            return _wk_check(stored_hash, plain)
        except Exception:
            return False

def _maybe_upgrade_hash(uid: int, stored_hash: str, plain: str):
    """On successful login, migrate legacy hash to Argon2."""
    if not stored_hash.startswith("$argon2"):
        try:
            new_hash = _hash_password(plain)
            db_exec("UPDATE users SET password_hash=? WHERE id=?", (new_hash, uid))
            _audit("password_rehash", meta={"uid": uid})
        except Exception:
            pass

def create_user(username, email, password_hash, role="customer"):
    uid = db_exec(
        "INSERT INTO users (username,email,password_hash,role) VALUES (?,?,?,?)",
        (username, email, password_hash, role)
    )
    if role == "admin":
        db_exec("INSERT OR IGNORE INTO users_admin (user_id) VALUES (?)", (uid,))
    elif role == "seller":
        db_exec("INSERT OR IGNORE INTO users_seller (user_id) VALUES (?)", (uid,))
    else:
        db_exec("INSERT OR IGNORE INTO users_customer (user_id) VALUES (?)", (uid,))
    return uid

def change_role(uid, new_role):
    db_exec("UPDATE users SET role=? WHERE id=?", (new_role, uid))
    db_exec("DELETE FROM users_admin WHERE user_id=?", (uid,))
    db_exec("DELETE FROM users_seller WHERE user_id=?", (uid,))
    db_exec("DELETE FROM users_customer WHERE user_id=?", (uid,))
    if new_role == "admin":
        db_exec("INSERT OR IGNORE INTO users_admin (user_id) VALUES (?)", (uid,))
    elif new_role == "seller":
        db_exec("INSERT OR IGNORE INTO users_seller (user_id) VALUES (?)", (uid,))
    else:
        db_exec("INSERT OR IGNORE INTO users_customer (user_id) VALUES (?)", (uid,))

# Catalog / reviews / orders 
def list_products(q=None, status=None, limit=None, page=None, order=None, seller_id=None):
    where, params = [], []
    if q:
        like = f"%{q}%"
        where.append("(p.name LIKE ? OR p.description LIKE ?)")
        params += [like, like]
    if status == "in":
        where.append("p.stock > 10")
    elif status == "low":
        where.append("p.stock > 0 AND p.stock <= 10")
    elif status == "out":
        where.append("p.stock <= 0")
    if seller_id:
        where.append("p.seller_id = ?"); params.append(seller_id)

    sql = """
      SELECT p.*,
             COALESCE(a.avg_rating,0)   AS avg_rating,
             COALESCE(a.review_count,0) AS review_count
        FROM products p
   LEFT JOIN (
         SELECT product_id, AVG(rating) AS avg_rating, COUNT(*) AS review_count
           FROM reviews GROUP BY product_id
      ) a ON a.product_id = p.id
    """
    if where:
        sql += " WHERE " + " AND ".join(where)

    if order == "newest":
        sql += " ORDER BY p.created_at DESC"
    elif order == "price_asc":
        sql += " ORDER BY p.price ASC"
    elif order == "price_desc":
        sql += " ORDER BY p.price DESC"
    else:
        sql += " ORDER BY p.id DESC"

    if limit:
        sql += " LIMIT ?"; params.append(int(limit))
        if page and int(page) > 1:
            sql += " OFFSET ?"; params.append((int(page)-1) * int(limit))

    return db_query(sql, params)

def get_product(pid):
    return db_query("SELECT * FROM products WHERE id=?", (pid,), one=True)

def create_product(name, desc, price, stock, seller_id=None, image=None):
    return db_exec(
        "INSERT INTO products (name,description,price,stock,seller_id,image) VALUES (?,?,?,?,?,?)",
        (name, desc, price, stock, seller_id, image)
    )

def update_product(pid, name, desc, price, stock, image=None):
    if image is not None:
        db_exec("UPDATE products SET name=?,description=?,price=?,stock=?,image=? WHERE id=?",
                (name, desc, price, stock, image, pid))
    else:
        db_exec("UPDATE products SET name=?,description=?,price=?,stock=? WHERE id=?",
                (name, desc, price, stock, pid))

def delete_product(pid):
    db_exec("DELETE FROM products WHERE id=?", (pid,))

def get_reviews(pid):
    return db_query(
        "SELECT r.*, u.username FROM reviews r JOIN users u ON u.id=r.user_id "
        "WHERE r.product_id=? ORDER BY r.created_at DESC", (pid,)
    )

def create_review(pid, uid, rating, content, image=None, content_html=None):
    db_exec(
        "INSERT INTO reviews (product_id,user_id,rating,content,image,content_html) VALUES (?,?,?,?,?,?)",
        (pid, uid, rating, content, image, content_html)
    )

def record_order(product_id, buyer_id, quantity, total_price):
    db_exec(
        "INSERT INTO orders (product_id,buyer_id,quantity,total_price) VALUES (?,?,?,?)",
        (product_id, buyer_id, quantity, total_price)
    )

def list_orders_for_seller(seller_id):
    return db_query(
        """
        SELECT o.*, p.name AS product_name, u.username AS buyer_username
          FROM orders o
          JOIN products p ON p.id=o.product_id
     LEFT JOIN users u ON u.id=o.buyer_id
         WHERE p.seller_id=?
      ORDER BY o.created_at DESC
        """, (seller_id,)
    )

# Uploads 
def sanitize_filename(fn):
    fn = secure_filename(fn or "")
    _, ext = os.path.splitext(fn)
    if not ext:
        ext = ".bin"
    return f"{secrets.token_hex(8)}{ext.lower()}"

def _validate_image_bytes(data: bytes) -> None:
    with Image.open(io.BytesIO(data)) as img:
        img.verify()
    with Image.open(io.BytesIO(data)) as _:
        _.load()

def save_upload(fs):
    if not fs or not fs.filename:
        return None
    name = sanitize_filename(fs.filename)
    ext = os.path.splitext(name)[1].lower()
    if ext not in (".jpg", ".jpeg", ".png", ".gif"):
        raise ValueError("Invalid file type")
    data = fs.read()
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("File too large (max 2MB)")
    try:
        _validate_image_bytes(data)
    except Exception:
        raise ValueError("Invalid or corrupted image file")
    path = os.path.join(UPLOAD_DIR, name)
    with open(path, "wb") as f:
        f.write(data)
    return name

# TOTP (2FA)
def _new_totp_secret():
    return secrets.token_hex(10)

def _totp_code(secret, for_time=None, step=30, digits=6):
    if not secret:
        return "000000"
    for_time = for_time or int(time.time())
    counter = int(for_time // step)
    key = bytes.fromhex(secret)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code_int = (int.from_bytes(h[o:o+4], "big") & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)

def _verify_totp(secret, code, leeway=1, step=30):
    if not secret or not code or not code.isdigit():
        return False
    now = int(time.time())
    for off in range(-leeway, leeway+1):
        if _totp_code(secret, now + off*step) == code:
            return True
    return False

def _b32_from_hex(hex_secret: str) -> str:
    if not hex_secret:
        return ""
    return base64.b32encode(bytes.fromhex(hex_secret)).decode().strip("=").upper()

def _otpauth_uri(user_email: str, hex_secret: str, issuer="SecureShop"):
    if not hex_secret:
        return ""
    b32 = _b32_from_hex(hex_secret)
    label = f"{issuer}:{user_email}"
    params = urlencode({"secret": b32, "issuer": issuer, "algorithm": "SHA1", "digits": 6, "period": 30})
    return f"otpauth://totp/{label}?{params}"

# Seed admin
def _ensure_admin_from_env():
    email = os.environ.get("ADMIN_EMAIL")
    pw    = os.environ.get("ADMIN_PASSWORD")
    if not email or not pw:
        return
    ex = get_user_by_email(email)
    if ex:
        return
    uid = create_user(username=email.split("@")[0], email=email,
                      password_hash=_hash_password(pw), role="admin")
    _audit("user_register", meta={"seed_admin": True, "email": email, "uid": uid})

# Audit panel reporting
def report_failed_logins_24h(limit=10):
    return db_query("""
        SELECT COALESCE(ip,'-') AS ip, COUNT(*) AS count
        FROM audit_events
        WHERE event_type='login_failure'
          AND ts >= datetime('now','-1 day')
        GROUP BY ip
        ORDER BY count DESC
        LIMIT ?
    """, (limit,))

def report_registrations_by_ip_7d(limit=10):
    return db_query("""
        SELECT COALESCE(ip,'-') AS ip, COUNT(*) AS count
        FROM audit_events
        WHERE event_type='user_register'
          AND ts >= datetime('now','-7 days')
        GROUP BY ip
        ORDER BY count DESC
        LIMIT ?
    """, (limit,))

def report_accounts_sharing_ip_24h(limit=10):
    return db_query("""
        SELECT ip, COUNT(DISTINCT user_id) AS users
        FROM audit_events
        WHERE ts >= datetime('now','-1 day')
          AND ip IS NOT NULL AND user_id IS NOT NULL
        GROUP BY ip
        HAVING users > 1
        ORDER BY users DESC
        LIMIT ?
    """, (limit,))

def report_accounts_sharing_ip_7d(limit=10):
    return db_query("""
        SELECT ip, COUNT(DISTINCT user_id) AS users
        FROM audit_events
        WHERE ts >= datetime('now','-7 days')
          AND ip IS NOT NULL AND user_id IS NOT NULL
        GROUP BY ip
        HAVING users > 1
        ORDER BY users DESC
        LIMIT ?
    """, (limit,))

def report_csrf_failures_24h(limit=10):
    return db_query("""
        SELECT COALESCE(ip,'-') AS ip, COUNT(*) AS count
        FROM audit_events
        WHERE event_type='csrf_failure'
          AND ts >= datetime('now','-1 day')
        GROUP BY ip
        ORDER BY count DESC
        LIMIT ?
    """, (limit,))

def report_csrf_failures_7d(limit=10):
    return db_query("""
        SELECT COALESCE(ip,'-') AS ip, COUNT(*) AS count
        FROM audit_events
        WHERE event_type='csrf_failure'
          AND ts >= datetime('now','-7 days')
        GROUP BY ip
        ORDER BY count DESC
        LIMIT ?
    """, (limit,))

def report_forbidden_by_user_7d(limit=10):
    return db_query("""
        SELECT COALESCE(users.email, users.username) AS user,
               ae.user_id,
               COUNT(*) AS count
        FROM audit_events ae
        LEFT JOIN users ON users.id = ae.user_id
        WHERE ae.event_type='forbidden'
          AND ae.ts >= datetime('now','-7 days')
        GROUP BY ae.user_id
        ORDER BY count DESC
        LIMIT ?
    """, (limit,))

__all__ = [
    # db
    "get_db", "db_query", "db_exec", "ensure_schema_and_migrations",
    # users/security
    "User", "get_user_by_email", "get_user_by_username", "set_last_login",
    "_hash_password", "_verify_password", "_maybe_upgrade_hash",
    "create_user", "change_role",
    # catalog/reviews/orders
    "list_products", "get_product", "create_product", "update_product", "delete_product",
    "get_reviews", "create_review", "record_order", "list_orders_for_seller",
    # uploads
    "sanitize_filename", "save_upload",
    # audit
    "log_audit", "_audit", "audit_page",
    # 2FA
    "_new_totp_secret", "_totp_code", "_verify_totp", "_b32_from_hex", "_otpauth_uri",
    # seed
    "_ensure_admin_from_env",
    # reporting
    "report_failed_logins_24h", "report_registrations_by_ip_7d",
    "report_accounts_sharing_ip_24h", "report_accounts_sharing_ip_7d",
    "report_csrf_failures_24h", "report_csrf_failures_7d",
    "report_forbidden_by_user_7d",
    # paths
    "BASE_DIR", "DB_PATH", "UPLOAD_DIR", "LOG_PATH",
]
