import io, csv, time, secrets, functools, hmac
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from urllib.parse import urlencode, urlparse

from flask import render_template, request, redirect, url_for, flash, session, send_file, abort
from flask_login import login_user, logout_user, login_required, current_user
import bleach

from __init__ import app, limiter, login_manager, IS_PROD
from models import (
    ensure_schema_and_migrations, db_query, db_exec,
    create_user, change_role, get_user_by_email, get_user_by_username, set_last_login,
    list_products, get_product, create_product, update_product, delete_product,
    get_reviews, create_review, record_order, list_orders_for_seller, save_upload,
    _hash_password, _verify_password, _maybe_upgrade_hash,
    _verify_totp, _new_totp_secret, _otpauth_uri,
    _audit, audit_page, User, _ensure_admin_from_env, log_audit,
    _b32_from_hex
)

# utils
def _int_or_400(v, *, minv=None, maxv=None):
    try:
        n = int(v)
    except Exception:
        abort(400)
    if minv is not None and n < minv: n = minv
    if maxv is not None and n > maxv: n = maxv
    return n

def _arg_int(name, default=None, *, minv=None, maxv=None):
    raw = request.args.get(name)
    return _int_or_400(raw, minv=minv, maxv=maxv) if (raw not in (None, "")) else (default if default is not None else (minv if minv is not None else 0))

def _form_int(name, default=None, *, minv=None, maxv=None):
    raw = request.form.get(name)
    return _int_or_400(raw, minv=minv, maxv=maxv) if (raw not in (None, "")) else (default if default is not None else (minv if minv is not None else 0))

def _parse_price_or_400(raw):
    try:
        d = Decimal(str(raw)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, TypeError):
        abort(400)
    if d < 0: abort(400)
    return d

def _is_safe_next(nxt):
    if not nxt: return False
    try:
        u = urlparse(nxt)
        return not u.netloc and nxt.startswith("/")
    except Exception:
        return False

# CSRF 
def _ensure_csrf():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(24)

@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        _ensure_csrf()
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
        if not sent or not hmac.compare_digest(sent, session.get("_csrf", "")):
            _audit("csrf_failure", meta={"path": request.path})
            abort(400)

@app.context_processor
def inject_csrf():
    _ensure_csrf()
    return {"csrf_token": lambda: session.get("_csrf", "")}

# session freshness
def _rotate_session():
    old = session.get("_csrf")
    session.clear()
    session["_csrf"] = old or secrets.token_urlsafe(24)
    session["_sid"] = secrets.token_hex(16)
    session.permanent = True

def _mark_fresh(): session["fresh_at"] = int(time.time())

def _is_fresh(sec=300):
    try:
        return int(time.time()) - int(session.get("fresh_at", 0)) <= sec
    except Exception:
        return False

# user loader
@login_manager.user_loader
def load_user(uid):
    r = db_query("SELECT * FROM users WHERE id=?", (uid,), one=True)
    return User(r) if r else None

# decorators
def admin_required(view):
    @functools.wraps(view)
    def w(*a, **k):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admin access required.", "warning")
            return redirect(url_for("home"))
        return view(*a, **k)
    return w

def seller_required(view):
    @functools.wraps(view)
    def w(*a, **k):
        if not current_user.is_authenticated or not (current_user.is_seller or current_user.is_admin):
            flash("Seller access required.", "warning")
            return redirect(url_for("home"))
        return view(*a, **k)
    return w

def fresh_admin_required(view):
    @functools.wraps(view)
    def w(*a, **k):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admin access required.", "warning")
            return redirect(url_for("home"))
        if not _is_fresh(300):
            flash("Re-auth required for this admin action.", "warning")
            return redirect(url_for("twofactor") if getattr(current_user, "twofa_enabled", False) else url_for("login", next=request.path))
        return view(*a, **k)
    return w

# globals
@app.context_processor
def inject_globals():
    c = session.get("cart", {}) or {}
    return {"cart_count": sum(c.values())}

# public
@app.route("/")
@audit_page
def home():
    return render_template("home.html", products=list_products(limit=8, order="newest"))

@app.route("/all-products")
@audit_page
def all_products():
    q = (request.args.get("q", "") or "").strip()
    status = (request.args.get("status", "") or "").strip().lower()
    if status not in {"", "in", "low", "out", "all"}: status = ""
    page = _arg_int("page", 1, minv=1, maxv=1000); limit = 12
    prods = list_products(q=q, status=status, limit=limit, page=page, order="newest")
    total = (db_query("SELECT COUNT(*) AS c FROM products", one=True) or {"c": 0})["c"]
    pages = max(1, (total + limit - 1) // limit)
    return render_template("products.html", products=prods, page=page, pages=pages, total=total, status=status, q=q)

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return redirect(url_for("all_products", q=q) if q else url_for("all_products"))

@app.route("/product/<int:product_id>")
@audit_page
def product_detail(product_id):
    p = get_product(product_id)
    if not p: abort(404)
    can_review = False
    if current_user.is_authenticated:
        bought = db_query("SELECT 1 FROM orders WHERE buyer_id=? AND product_id=? LIMIT 1", (int(current_user.id), product_id), one=True)
        can_review = bool(bought)
    return render_template("product_detail.html", product=p, reviews=get_reviews(product_id), can_review=can_review)

# cart
@app.route("/cart")
@login_required
@audit_page
def view_cart():
    cart = session.get("cart", {}) or {}
    items, total = [], Decimal("0.00")
    for k, v in cart.items():
        try:
            pid, qty = int(k), int(v)
        except Exception:
            continue
        p = get_product(pid)
        if not p: continue
        price = _parse_price_or_400(p["price"])
        line = (price * qty).quantize(Decimal("0.01"))
        total = (total + line).quantize(Decimal("0.01"))
        items.append({
            "product_id": pid, "name": p["name"], "description": p["description"], "image": p["image"],
            "price_each": float(price), "quantity": qty, "line_total": float(line), "stock": int(p["stock"])
        })
    return render_template("basket.html", items=items, total=float(total), cart_count=sum(cart.values()))

@app.route("/cart/add/<int:product_id>", methods=["POST"])
@login_required
@limiter.limit("60/minute")
def cart_add(product_id):
    p = get_product(product_id)
    if not p or int(p["stock"]) <= 0:
        flash("This item is out of stock.", "warning")
        return redirect(url_for("product_detail", product_id=product_id))
    cart = session.get("cart", {}) or {}
    cart[str(product_id)] = cart.get(str(product_id), 0) + 1
    session["cart"] = cart
    _audit("add_to_cart", product_id=product_id)
    flash("Added to basket.", "success")
    return redirect(url_for("product_detail", product_id=product_id))

@app.route("/cart/update", methods=["POST"])
@login_required
@limiter.limit("60/minute")
def cart_update():
    pid = _form_int("product_id", 0, minv=0, maxv=10**9)
    qty = max(1, _form_int("qty", 1, minv=1, maxv=1000))
    cart = session.get("cart", {}) or {}
    if str(pid) in cart:
        cart[str(pid)] = qty
        session["cart"] = cart
        _audit("cart_update", product_id=pid, meta={"qty": qty})
    return redirect(url_for("view_cart"))

@app.route("/cart/remove/<int:product_id>", methods=["POST"])
@login_required
@limiter.limit("60/minute")
def cart_remove(product_id):
    cart = session.get("cart", {}) or {}
    if str(product_id) in cart:
        cart.pop(str(product_id))
        session["cart"] = cart
        _audit("cart_remove", product_id=product_id)
    return redirect(url_for("view_cart"))

@app.route("/cart/checkout", methods=["POST"])
@login_required
@limiter.limit("10/minute")
def cart_checkout():
    cart = session.get("cart", {}) or {}
    if not cart:
        flash("Your basket is empty.", "info")
        return redirect(url_for("view_cart"))
    for pid_str, qty in cart.items():
        try:
            pid, qty = int(pid_str), int(qty)
        except Exception:
            continue
        p = get_product(pid)
        if not p: continue
        price = _parse_price_or_400(p["price"])
        total = (price * qty).quantize(Decimal("0.01"))
        record_order(pid, int(current_user.id), qty, float(total))
        update_product(pid, p["name"], p["description"], float(price), max(0, int(p["stock"]) - qty), image=p["image"])
    session["cart"] = {}
    _audit("purchase", meta={"items": cart})
    flash("Purchase completed (demo).", "success")
    return redirect(url_for("home"))

# reviews
_ALLOWED_TAGS = ["b", "i", "u", "strong", "em", "ul", "ol", "li", "br", "p"]
_ALLOWED_ATTRS = {}
_ALLOWED_PROTOCOLS = ["http", "https"]
def _sanitize_html(txt): return bleach.clean(txt or "", tags=_ALLOWED_TAGS, attributes=_ALLOWED_ATTRS, protocols=_ALLOWED_PROTOCOLS, strip=True)

@app.route("/product/<int:product_id>/reviews", methods=["POST"])
@login_required
@limiter.limit("30/minute")
def add_review(product_id):
    if not get_product(product_id): abort(404)
    image = None
    if "image" in request.files and request.files["image"].filename:
        try:
            image = save_upload(request.files["image"])
        except Exception as e:
            flash(str(e), "warning")
            return redirect(url_for("product_detail", product_id=product_id))
    bought = db_query("SELECT 1 FROM orders WHERE buyer_id=? AND product_id=? LIMIT 1", (int(current_user.id), product_id), one=True)
    if not bought:
        flash("You can review this item after you’ve purchased it.", "warning")
        return redirect(url_for("product_detail", product_id=product_id))
    rating = _form_int("rating", 5, minv=1, maxv=5)
    content = (request.form.get("content", "") or "").strip()
    create_review(product_id, int(current_user.id), rating, content, image=image, content_html=_sanitize_html(content))
    _audit("review_create", product_id=product_id, meta={"rating": rating})
    flash("Thanks for your review!", "success")
    return redirect(url_for("product_detail", product_id=product_id))

# auth
@app.route("/login", methods=["GET"])
@audit_page
def login():
    return render_template("auth.html", mode="login")

def _rl_key_ip():
    ip = request.headers.get("X-Forwarded-For", "") or request.remote_addr or "unknown"
    if "," in ip: ip = ip.split(",")[0].strip()
    return f"ip:{ip}"

def _rl_key_account():
    ident = (request.form.get("username", "") or request.args.get("username", "") or "").strip().lower()
    return f"acct:{ident or 'none'}"

@app.route("/login", methods=["POST"])
@limiter.limit("5/minute", key_func=_rl_key_ip)
@limiter.limit("20/hour", key_func=_rl_key_account)
def login_post():
    ident = (request.form.get("username", "") or "").strip()
    password = request.form.get("password", "") or ""
    nxt = request.form.get("next") or request.args.get("next")
    user = get_user_by_username(ident) or get_user_by_email(ident)

    now = int(time.time())
    if user and (user["locked_until"] or 0) and int(user["locked_until"]) > now:
        flash("Account temporarily locked. Try again later.", "danger")
        _audit("login_locked", meta={"uid": int(user["id"])})
        return redirect(url_for("login"))

    if not user or not _verify_password(user["password_hash"], password):
        if user:
            log_audit("login_failure", route=request.path, method=request.method, user_id=int(user["id"]),
                      ip=(request.headers.get("X-Forwarded-For", request.remote_addr)),
                      ua=request.headers.get("User-Agent"), session_id=session.get("_sid"),
                      meta={"username": ident})
            acc_fails = db_query(
                "SELECT COUNT(*) AS c FROM audit_events WHERE event_type='login_failure' AND user_id=? AND ts >= datetime('now','-10 minutes')",
                (int(user["id"]),), one=True) or {"c": 0}
            if int(acc_fails["c"]) >= 5:
                lock_secs = 600
                db_exec("UPDATE users SET locked_until=? WHERE id=?", (now + lock_secs, int(user["id"])))
                _audit("account_lockout", meta={"uid": int(user["id"]), "duration": lock_secs})
        else:
            _audit("login_failure", meta={"username": ident})
        flash("Invalid credentials.", "danger")
        return redirect(url_for("login", next=nxt) if (nxt and _is_safe_next(nxt)) else url_for("login"))

    _maybe_upgrade_hash(int(user["id"]), user["password_hash"], password)
    if user["twofa_enabled"]:
        session["otp_pending"] = int(user["id"])
        _audit("login_success", meta={"step": "password_ok"})
        return redirect(url_for("twofactor"))

    _rotate_session(); login_user(User(user)); set_last_login(int(user["id"]))
    db_exec("UPDATE users SET locked_until=NULL WHERE id=?", (int(user["id"]),))
    _mark_fresh(); _audit("login_success"); flash("Signed in.", "success")
    return redirect(nxt if _is_safe_next(nxt) else url_for("home"))

@app.route("/twofactor", methods=["GET", "POST"])
@limiter.limit("10/minute")
def twofactor():
    if request.method == "GET":
        return render_template("auth.html", mode="twofactor")
    code = (request.form.get("otp", "") or "").strip()
    pending = session.get("otp_pending")
    if not pending:
        flash("No pending login.", "warning")
        return redirect(url_for("login"))
    user = db_query("SELECT * FROM users WHERE id=?", (pending,), one=True)
    if not user:
        session.pop("otp_pending", None)
        flash("Account not found.", "danger")
        return redirect(url_for("login"))
    if not _verify_totp(user["twofa_secret"], code):
        _audit("login_failure_2fa", meta={"uid": pending})
        flash("Invalid code.", "danger")
        return redirect(url_for("twofactor"))
    session.pop("otp_pending", None)
    _rotate_session(); login_user(User(user)); set_last_login(int(user["id"]))
    db_exec("UPDATE users SET locked_until=NULL WHERE id=?", (int(user["id"]),))
    _mark_fresh(); _audit("login_success_2fa"); flash("Signed in with 2FA.", "success")
    return redirect(url_for("home"))

@app.route("/register", methods=["GET"])
@audit_page
def register():
    return render_template("auth.html", mode="register")

@app.route("/register", methods=["POST"])
@limiter.limit("10/minute")
def register_post():
    username = (request.form.get("username", "") or "").strip()
    email = (request.form.get("email", "") or "").strip().lower()
    password = request.form.get("password", "") or ""
    confirm = request.form.get("confirm", "") or ""
    COMMON = {"password","password1","passw0rd","123456","1234567","12345678","123456789","111111",
              "qwerty","abc123","letmein","admin","welcome","iloveyou","monkey","dragon","football",
              "baseball","princess","sunshine","login","starwars","freedom","hello","whatever",
              "qwerty123","1q2w3e4r","zaq12wsx","trustno1"}
    if len(password) < 10:
        flash("Use a password of at least 10 characters.", "warning"); return redirect(url_for("register"))
    if password.lower() in COMMON:
        flash("Password too common. Choose a stronger one.", "warning"); return redirect(url_for("register"))
    if password != confirm:
        flash("Passwords do not match.", "danger"); return redirect(url_for("register"))
    if get_user_by_email(email) or get_user_by_username(username):
        flash("Username or email already in use.", "warning"); return redirect(url_for("register"))
    uid = create_user(username, email, _hash_password(password), role="customer")
    _audit("user_register", meta={"uid": uid}); flash("Account created. Please sign in.", "success")
    return redirect(url_for("login"))

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user(); _audit("logout"); flash("Signed out.", "success")
    return redirect(url_for("home"))

# profile / 2FA / roles
@app.route("/profile")
@login_required
@audit_page
def profile():
    r = db_query("SELECT username,email,twofa_enabled,twofa_secret FROM users WHERE id=?", (int(current_user.id),), one=True)
    enabled = bool(r["twofa_enabled"]) if r else False
    otpauth = _otpauth_uri(r["email"], r["twofa_secret"]) if (r and r["twofa_secret"]) else None
    b32 = _b32_from_hex(r["twofa_secret"]) if (r and r["twofa_secret"]) else None
    return render_template("profile.html", twofa_enabled=enabled, setup_key=b32, otpauth_url=otpauth, qr_path=None)

@app.route("/enable_2fa", methods=["POST"])
@login_required
def enable_2fa():
    r = db_query("SELECT twofa_secret FROM users WHERE id=?", (int(current_user.id),), one=True)
    if not r or not r["twofa_secret"]:
        db_exec("UPDATE users SET twofa_secret=?, twofa_enabled=1 WHERE id=?", (_new_totp_secret(), int(current_user.id)))
    else:
        db_exec("UPDATE users SET twofa_enabled=1 WHERE id=?", (int(current_user.id),))
    _audit("2fa_enable"); flash("2FA enabled. Scan the key shown on this page with your Authenticator app.", "success")
    return redirect(url_for("profile"))

@app.route("/disable_2fa", methods=["POST"])
@login_required
def disable_2fa():
    db_exec("UPDATE users SET twofa_enabled=0 WHERE id=?", (int(current_user.id),))
    _audit("2fa_disable"); flash("2FA disabled.", "info"); return redirect(url_for("profile"))

@app.route("/become_seller", methods=["POST"])
@login_required
def become_seller():
    if current_user.role == "customer":
        change_role(int(current_user.id), "seller"); _rotate_session()
        _audit("role_change_self", meta={"to": "seller"}); flash("You're now a seller.", "success")
    return redirect(url_for("profile"))

# seller
@app.route("/seller/products")
@login_required
@seller_required
@audit_page
def seller_products():
    return render_template("seller_dashboard.html", products=list_products(seller_id=int(current_user.id), order="newest"))

@app.route("/seller/add", methods=["GET", "POST"])
@login_required
@seller_required
@limiter.limit("60/minute")
def seller_add_product():
    if request.method == "GET":
        return render_template("product_form.html", product=None, back_url=url_for("seller_products"))
    name = (request.form.get("name", "") or "").strip()
    desc = (request.form.get("description", "") or "").strip()
    price = _parse_price_or_400(request.form.get("price", "0") or 0)
    stock = _form_int("stock", 0, minv=0, maxv=10**9)
    image = None
    if "image" in request.files and request.files["image"].filename:
        try:
            image = save_upload(request.files["image"])
        except Exception as e:
            flash(str(e), "warning"); return redirect(url_for("seller_add_product"))
    pid = create_product(name, desc, float(price), stock, seller_id=int(current_user.id), image=image)
    _audit("product_create", product_id=pid); flash("Product created.", "success")
    return redirect(url_for("seller_products"))

@app.route("/seller/edit/<int:product_id>", methods=["GET", "POST"])
@login_required
@seller_required
@limiter.limit("60/minute")
def seller_edit_product(product_id):
    p = get_product(product_id)
    if not p: abort(404)
    if not (current_user.is_admin or int(p["seller_id"] or 0) == int(current_user.id)):
        flash("Not allowed.", "danger"); return redirect(url_for("seller_products"))
    if request.method == "GET":
        return render_template("product_form.html", product=p, back_url=url_for("seller_products"))
    name = (request.form.get("name", "") or "").strip()
    desc = (request.form.get("description", "") or "").strip()
    price = _parse_price_or_400(request.form.get("price", "0") or 0)
    stock = _form_int("stock", 0, minv=0, maxv=10**9)
    image = None
    if "image" in request.files and request.files["image"].filename:
        try:
            image = save_upload(request.files["image"])
        except Exception as e:
            flash(str(e), "warning"); return redirect(url_for("seller_edit_product", product_id=product_id))
    update_product(product_id, name, desc, float(price), stock, image=image)
    _audit("product_update", product_id=product_id); flash("Product updated.", "success")
    return redirect(url_for("seller_products"))

@app.route("/seller/delete/<int:product_id>", methods=["POST"])
@login_required
@seller_required
@limiter.limit("60/minute")
def seller_delete_product(product_id):
    p = get_product(product_id)
    if not p: abort(404)
    if not (current_user.is_admin or int(p["seller_id"] or 0) == int(current_user.id)):
        flash("Not allowed.", "danger"); return redirect(url_for("seller_products"))
    delete_product(product_id); _audit("product_delete", product_id=product_id); flash("Product deleted.", "info")
    return redirect(url_for("seller_products"))

@app.route("/seller/orders")
@login_required
@seller_required
@audit_page
def seller_orders():
    return render_template("seller_orders.html", orders=list_orders_for_seller(int(current_user.id)))

# admin
@app.route("/admin")
@login_required
@admin_required
@audit_page
def admin_dashboard():
    counts = {k: db_query(f"SELECT COUNT(*) AS c FROM {k}", one=True)["c"] for k in ("users", "products", "orders")}
    counts["suspicious"] = db_query("SELECT COUNT(*) AS c FROM suspicious_activities", one=True)["c"]
    totals = {
        "page_views": db_query("SELECT COUNT(*) AS c FROM audit_events WHERE event_type='page_view' AND ts >= datetime('now','-7 days')", one=True)["c"],
        "product_views": db_query("SELECT COUNT(*) AS c FROM audit_events WHERE event_type='page_view' AND route LIKE '/product/%' AND ts >= datetime('now','-7 days')", one=True)["c"],
        "basket_adds": db_query("SELECT COUNT(*) AS c FROM audit_events WHERE event_type='add_to_cart' AND ts >= datetime('now','-7 days')", one=True)["c"],
        "reviews": db_query("SELECT COUNT(*) AS c FROM reviews WHERE created_at >= datetime('now','-7 days')", one=True)["c"],
        "orders": db_query("SELECT COUNT(*) AS c FROM orders WHERE created_at >= datetime('now','-7 days')", one=True)["c"],
        "revenue": db_query("SELECT COALESCE(SUM(total_price),0) AS s FROM orders WHERE created_at >= datetime('now','-7 days')", one=True)["s"] or 0.0,
    }
    users_map = {r["id"]: (r["email"] or r["username"]) for r in db_query("SELECT id,username,email FROM users")}
    per_user = {}
    def bump(uid, key, inc=1, val=None):
        if uid is None: return
        row = per_user.setdefault(uid, {"user": users_map.get(uid, f"uid:{uid}"), "page_views": 0, "product_views": 0, "basket_adds": 0, "reviews": 0, "orders": 0, "revenue": 0.0})
        row[key] += float(val) if val is not None else inc
    for r in db_query("SELECT user_id, COUNT(*) AS c FROM audit_events WHERE event_type='page_view' AND user_id IS NOT NULL AND ts >= datetime('now','-7 days') GROUP BY user_id"): bump(r["user_id"], "page_views", inc=r["c"])
    for r in db_query("SELECT user_id, COUNT(*) AS c FROM audit_events WHERE event_type='page_view' AND user_id IS NOT NULL AND route LIKE '/product/%' AND ts >= datetime('now','-7 days') GROUP BY user_id"): bump(r["user_id"], "product_views", inc=r["c"])
    for r in db_query("SELECT user_id, COUNT(*) AS c FROM audit_events WHERE event_type='add_to_cart' AND user_id IS NOT NULL AND ts >= datetime('now','-7 days') GROUP BY user_id"): bump(r["user_id"], "basket_adds", inc=r["c"])
    for r in db_query("SELECT user_id, COUNT(*) AS c FROM reviews WHERE created_at >= datetime('now','-7 days') GROUP BY user_id"): bump(r["user_id"], "reviews", inc=r["c"])
    for r in db_query("SELECT buyer_id AS user_id, COUNT(*) AS c, COALESCE(SUM(total_price),0) AS s FROM orders WHERE created_at >= datetime('now','-7 days') GROUP BY buyer_id"):
        bump(r["user_id"], "orders", inc=r["c"]); bump(r["user_id"], "revenue", val=r["s"])
    recent_raw = db_query("SELECT ts,event_type,route,meta,user_id FROM audit_events ORDER BY ts DESC LIMIT 20")
    recent = [{"ts": r["ts"], "event_type": r["event_type"], "route": r["route"], "meta": r["meta"], "user": users_map.get(r["user_id"], "-") if r["user_id"] is not None else "-"} for r in recent_raw]
    return render_template("admin_dashboard.html",
        counts=counts, activity_totals=totals,
        suspicious_preview=db_query("SELECT category, COUNT(*) AS count FROM suspicious_activities WHERE ts >= datetime('now','-1 day') GROUP BY category ORDER BY count DESC LIMIT 6"),
        pageviews=sorted(per_user.values(), key=lambda x: (x["page_views"], x["product_views"], x["orders"], x["revenue"]), reverse=True),
        recent_events=recent)

@app.route("/admin/products")
@login_required
@admin_required
@audit_page
def admin_products():
    # filters + pagination
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    page = _arg_int("page", 1, minv=1, maxv=1000)
    per_page = 20

    products = list_products(q=q, status=status, limit=per_page, page=page, order="newest")

   
    where, params = [], []
    if q:
        like = f"%{q}%"
        where.append("(name LIKE ? OR description LIKE ?)")
        params += [like, like]
    if status == "in":
        where.append("stock > 10")
    elif status == "low":
        where.append("stock > 0 AND stock <= 10")
    elif status == "out":
        where.append("stock <= 0")

    count_sql = "SELECT COUNT(*) AS c FROM products"
    if where: count_sql += " WHERE " + " AND ".join(where)
    total = (db_query(count_sql, params, one=True) or {"c": 0})["c"]
    pages = max(1, (int(total) + per_page - 1) // per_page)

    return render_template("admin_products.html", products=products, page=page, pages=pages)

@app.route("/admin/products/add", methods=["GET", "POST"])
@login_required
@admin_required
@fresh_admin_required
@limiter.limit("10/minute")
def admin_add_product():
    if request.method == "GET":
        return render_template("product_form.html", product=None, back_url=url_for("admin_products"))
    name = (request.form.get("name", "") or "").strip()
    desc = (request.form.get("description", "") or "").strip()
    price = _parse_price_or_400(request.form.get("price", "0") or 0)
    stock = _form_int("stock", 0, minv=0, maxv=10**9)
    image = None
    if "image" in request.files and request.files["image"].filename:
        try:
            image = save_upload(request.files["image"])
        except Exception as e:
            flash(str(e), "warning"); return redirect(url_for("admin_add_product"))
    pid = create_product(name, desc, float(price), stock, seller_id=int(current_user.id), image=image)
    _audit("product_create", product_id=pid); flash("Product created.", "success")
    return redirect(url_for("admin_products"))

@app.route("/admin/products/<int:product_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
@fresh_admin_required
@limiter.limit("10/minute")
def admin_edit_product(product_id):
    p = get_product(product_id)
    if not p: abort(404)
    if request.method == "GET":
        return render_template("product_form.html", product=p, back_url=url_for("admin_products"))
    name = (request.form.get("name", "") or "").strip()
    desc = (request.form.get("description", "") or "").strip()
    price = _parse_price_or_400(request.form.get("price", "0") or 0)
    stock = _form_int("stock", 0, minv=0, maxv=10**9)
    image = None
    if "image" in request.files and request.files["image"].filename:
        try:
            image = save_upload(request.files["image"])
        except Exception as e:
            flash(str(e), "warning"); return redirect(url_for("admin_edit_product", product_id=product_id))
    update_product(product_id, name, desc, float(price), stock, image=image)
    _audit("product_update", product_id=product_id); flash("Product updated.", "success")
    return redirect(url_for("admin_products"))

@app.route("/admin/products/<int:product_id>/delete", methods=["POST"])
@login_required
@admin_required
@fresh_admin_required
@limiter.limit("10/minute")
def admin_delete_product(product_id):
    delete_product(product_id); _audit("product_delete", product_id=product_id); flash("Product deleted.", "info")
    return redirect(url_for("admin_products"))

@app.route("/admin/users")
@login_required
@admin_required
@audit_page
def admin_users():
    q = (request.args.get("q") or "").strip()
    role = (request.args.get("role") or "").strip()
    page = _arg_int("page", 1, minv=1, maxv=1000)
    per_page = 25

    where, params = [], []
    if q:
        like = f"%{q}%"
        where.append("(username LIKE ? OR email LIKE ?)")
        params += [like, like]
    if role in ("customer", "seller", "admin"):
        where.append("role = ?")
        params.append(role)

    count_sql = "SELECT COUNT(*) AS c FROM users"
    if where: count_sql += " WHERE " + " AND ".join(where)
    total = (db_query(count_sql, params, one=True) or {"c": 0})["c"]
    pages = max(1, (int(total) + per_page - 1) // per_page)

    sql = "SELECT id,username,email,role,twofa_enabled FROM users"
    if where: sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    users = db_query(sql, params + [per_page, (page - 1) * per_page])

    return render_template("admin_users.html", users=users, page=page, pages=pages)

@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@login_required
@admin_required
@fresh_admin_required
@limiter.limit("10/minute")
def admin_update_user_role(user_id):
    # block self role change
    if int(current_user.id) == int(user_id):
        flash("You cannot change your own role.", "warning")
        return redirect(url_for("admin_users"))

    role = request.form.get("role", "customer")
    if role not in ("customer", "seller", "admin"):
        flash("Invalid role.", "danger")
        return redirect(url_for("admin_users"))

    target = db_query("SELECT role FROM users WHERE id=?", (user_id,), one=True)
    if not target:
        flash("User not found.", "danger")
        return redirect(url_for("admin_users"))

    # protect last admin from demotion
    if target["role"] == "admin" and role != "admin":
        admins = (db_query("SELECT COUNT(*) AS c FROM users WHERE role='admin'", one=True) or {"c": 0})["c"]
        if int(admins) <= 1:
            flash("Cannot demote the last admin.", "warning")
            return redirect(url_for("admin_users"))

    change_role(user_id, role)
    _audit("admin_role_change", meta={"user_id": user_id, "role": role})
    flash("Role updated.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
@fresh_admin_required
@limiter.limit("10/minute")
def admin_delete_user(user_id):
    # block self delete
    if int(current_user.id) == int(user_id):
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for("admin_users"))

    target = db_query("SELECT role FROM users WHERE id=?", (user_id,), one=True)
    if not target:
        flash("User not found.", "danger")
        return redirect(url_for("admin_users"))

    # protect last admin
    if target["role"] == "admin":
        admins = (db_query("SELECT COUNT(*) AS c FROM users WHERE role='admin'", one=True) or {"c": 0})["c"]
        if int(admins) <= 1:
            flash("Cannot delete the last admin.", "warning")
            return redirect(url_for("admin_users"))

    for t in ("users", "users_admin", "users_seller", "users_customer"):
        db_exec(f"DELETE FROM {t} WHERE {'id' if t=='users' else 'user_id'}=?", (user_id,))
    _audit("admin_user_delete", meta={"user_id": user_id})
    flash("User deleted.", "info")
    return redirect(url_for("admin_users"))

@app.route("/admin/audit")
@login_required
@admin_required
@audit_page
def admin_audit():
    q = (request.args.get("q", "") or "").strip()
    et = request.args.get("event_type", ""); method = request.args.get("method", "")
    user_id = request.args.get("user_id", ""); session_id = (request.args.get("session_id", "") or "").strip()
    product_id = request.args.get("product_id", ""); date_from = request.args.get("date_from", ""); date_to = request.args.get("date_to", "")
    limit = _arg_int("limit", 200, minv=10, maxv=2000); page = _arg_int("page", 1, minv=1, maxv=10000)

    where, params = [], []
    if q:
        like = f"%{q}%"; where.append("(route LIKE ? OR meta LIKE ? OR method LIKE ?)")
        params += [like, like, like]
    if et: where.append("event_type=?"); params.append(et)
    if method: where.append("method=?"); params.append(method)
    if user_id: where.append("user_id=?"); params.append(_int_or_400(user_id, minv=0, maxv=10**12))
    if session_id: where.append("session_id LIKE ?"); params.append(f"%{session_id}%")
    if product_id: where.append("product_id=?"); params.append(_int_or_400(product_id, minv=0, maxv=10**12))
    if date_from: where.append("DATE(ts)>=DATE(?)"); params.append(date_from)
    if date_to: where.append("DATE(ts)<=DATE(?)"); params.append(date_to)

    sql = "SELECT * FROM audit_events"
    if where: sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts DESC LIMIT ?"; params.append(limit)
    if page > 1: sql += " OFFSET ?"; params.append((page - 1) * limit)
    events = db_query(sql, params)

    base_args = request.args.to_dict(flat=True)
    def page_url(n): p = base_args.copy(); p["page"] = str(n); p["limit"] = str(limit); return url_for("admin_audit") + "?" + urlencode(p)
    prev_url = page_url(page - 1) if page > 1 else None
    next_url = page_url(page + 1) if len(events) == limit else None

    s_q = (request.args.get("s_q", "") or "").strip(); s_severity = request.args.get("s_severity", ""); s_category = request.args.get("s_category", "")
    s_ip = (request.args.get("s_ip", "") or "").strip(); s_user_id = request.args.get("s_user_id", ""); s_session_id = (request.args.get("s_session_id", "") or "").strip()
    s_date_from = request.args.get("s_date_from", ""); s_date_to = request.args.get("s_date_to", ""); s_limit = _arg_int("s_limit", 200, minv=10, maxv=2000); s_page = _arg_int("s_page", 1, minv=1, maxv=10000)

    s_where, s_params = [], []
    if s_q: sl = f"%{s_q}%"; s_where.append("(reason LIKE ? OR meta LIKE ? OR route LIKE ?)"); s_params += [sl, sl, sl]
    if s_severity: s_where.append("severity=?"); s_params.append(s_severity)
    if s_category: s_where.append("category=?"); s_params.append(s_category)
    if s_ip: s_where.append("ip LIKE ?"); s_params.append(f"%{s_ip}%")
    if s_user_id: s_where.append("user_id=?"); s_params.append(_int_or_400(s_user_id, minv=0, maxv=10**12))
    if s_session_id: s_where.append("session_id LIKE ?"); s_params.append(f"%{s_session_id}%")
    if s_date_from: s_where.append("DATE(ts)>=DATE(?)"); s_params.append(s_date_from)
    if s_date_to: s_where.append("DATE(ts)<=DATE(?)"); s_params.append(s_date_to)

    s_sql = "SELECT * FROM suspicious_activities"
    if s_where: s_sql += " WHERE " + " AND ".join(s_where)
    s_sql += " ORDER BY ts DESC, severity DESC LIMIT ?"; s_params.append(s_limit)
    if s_page > 1: s_sql += " OFFSET ?"; s_params.append((s_page - 1) * s_limit)
    items = db_query(s_sql, s_params)

    def s_page_url(n): p = base_args.copy(); p["s_page"] = str(n); p["s_limit"] = str(s_limit); return url_for("admin_audit") + "?" + urlencode(p)
    s_prev = s_page_url(s_page - 1) if s_page > 1 else None
    s_next = s_page_url(s_page + 1) if len(items) == s_limit else None

    return render_template("admin_audit.html",
        events=events, page=page, limit=limit, prev_url=prev_url, next_url=next_url,
        items=items, s_page=s_page, s_limit=s_limit, s_prev_url=s_prev, s_next_url=s_next,
        recent=db_query("SELECT * FROM suspicious_recent LIMIT 90"),
        by_ip=db_query("SELECT * FROM suspicious_by_ip LIMIT 50"),
        by_user=db_query("SELECT * FROM suspicious_by_user LIMIT 50"),
        hourly=db_query("SELECT * FROM suspicious_hourly LIMIT 48"))

@app.route("/admin/audit/export")
@login_required
@admin_required
def admin_audit_export():
    rows = db_query("SELECT * FROM audit_events ORDER BY ts DESC LIMIT 5000")
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["ts","event_type","user_id","route","method","product_id","ms","ip","ua","session_id","meta"])
    for r in rows:
        w.writerow([r["ts"],r["event_type"],r["user_id"],r["route"],r["method"],r["product_id"],r["ms"],r["ip"],r["ua"],r["session_id"],r["meta"]])
    out.seek(0); _audit("admin_audit_export", meta={"rows": len(rows)})
    return send_file(io.BytesIO(out.getvalue().encode("utf-8")), mimetype="text/csv", as_attachment=True, download_name="audit_export.csv")

@app.route("/admin/suspicious/export")
@login_required
@admin_required
def admin_suspicious_export():
    rows = db_query("SELECT * FROM suspicious_activities ORDER BY ts DESC LIMIT 5000")
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["ts","severity","category","reason","score","event_id","user_id","ip","ua","session_id","route","method","meta"])
    for r in rows:
        w.writerow([r["ts"],r["severity"],r["category"],r["reason"],r["score"],r["event_id"],r["user_id"],r["ip"],r["ua"],r["session_id"],r["route"],r["method"],r["meta"]])
    out.seek(0); _audit("admin_suspicious_export", meta={"rows": len(rows)})
    return send_file(io.BytesIO(out.getvalue().encode("utf-8")), mimetype="text/csv", as_attachment=True, download_name="suspicious_export.csv")

# errors
@app.errorhandler(400)
def e400(e): return render_template("error.html", code=400, message="Bad request."), 400

@app.errorhandler(403)
def e403(e): return render_template("error.html", code=403, message="Forbidden."), 403

@app.errorhandler(404)
def e404(e): return render_template("error.html", code=404, message="Not found."), 404

@app.errorhandler(413)
def e413(e): return render_template("error.html", code=413, message="File too large (max 2MB)."), 200

@app.errorhandler(429)
def e429(e):
    _audit("rate_limited", meta={"path": request.path if request else None})
    return render_template("error.html", code=429, message="Too many requests."), 429

@app.errorhandler(500)
def e500(e): return render_template("error.html", code=500, message="Something went wrong."), 500

# boot
if __name__ == "__main__":
    ensure_schema_and_migrations()
    if IS_PROD:
        app.config.update(SESSION_COOKIE_SECURE=True)
    with app.app_context():
        from secrets import token_hex
        with app.test_request_context("/__startup__"):
            session.setdefault("_sid", token_hex(16))
            _ensure_admin_from_env()

    app.run(host="127.0.0.1", port=5000, debug=not IS_PROD)
