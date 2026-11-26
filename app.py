import os, re, time, json, uuid, sqlite3, secrets
from contextlib import closing
from decimal import Decimal, InvalidOperation
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

DB_PATH = os.path.join(BASE_DIR, "shop.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,
)

FLW_SECRET_KEY = os.getenv("FLW_SECRET_KEY", "").strip()
FLW_WEBHOOK_HASH = os.getenv("FLW_WEBHOOK_HASH", "").strip()
SITE_URL = os.getenv("SITE_URL", "http://127.0.0.1:5000").rstrip("/")
FLW_API = "https://api.flutterwave.com/v3"
ALLOWED_CURRENCIES = {"RWF", "USD"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?[0-9]{8,15}$")
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp"}

def db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with closing(db()) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          country TEXT NOT NULL DEFAULT 'RW',
          phone TEXT DEFAULT '',
          role TEXT NOT NULL CHECK(role IN ('BUYER','SELLER')),
          shop TEXT DEFAULT '',
          created REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS products(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          seller_id INTEGER NOT NULL REFERENCES users(id),
          title TEXT NOT NULL, description TEXT DEFAULT '',
          price TEXT NOT NULL, currency TEXT NOT NULL,
          image TEXT DEFAULT '', created REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          shop TEXT NOT NULL, buyer_email TEXT NOT NULL,
          sender_email TEXT NOT NULL, body TEXT NOT NULL, created REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS wallets(
          user_id INTEGER NOT NULL REFERENCES users(id),
          currency TEXT NOT NULL,
          balance TEXT NOT NULL DEFAULT '0',
          PRIMARY KEY(user_id,currency)
        );
        CREATE TABLE IF NOT EXISTS payments(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL REFERENCES users(id),
          tx_ref TEXT UNIQUE NOT NULL,
          amount TEXT NOT NULL, currency TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          flw_id TEXT DEFAULT '', created REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS wallet_transactions(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL REFERENCES users(id),
          kind TEXT NOT NULL, amount TEXT NOT NULL,
          currency TEXT NOT NULL, reference TEXT NOT NULL,
          created REAL NOT NULL
        );
        """)
        for cur in ALLOWED_CURRENCIES:
            # Existing users receive a zero wallet lazily via wallet endpoint.
            pass
        c.commit()

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    with closing(db()) as c:
        return c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def user_json(u):
    return {"id": u["id"], "email": u["email"], "country": u["country"],
            "phone": u["phone"], "role": u["role"], "shop": u["shop"]}

def json_body():
    return request.get_json(silent=True) if request.is_json else None

def money(value):
    try:
        d = Decimal(str(value))
    except (InvalidOperation, TypeError):
        raise ValueError("Amafaranga wanditse si yo.")
    if not d.is_finite() or d <= 0 or d > Decimal("100000000000"):
        raise ValueError("Amafaranga agomba kuba arenze zero.")
    return d.quantize(Decimal("0.01"))

def flw_call(method, path, payload=None):
    if not FLW_SECRET_KEY:
        raise RuntimeError("FLW_SECRET_KEY ntiri muri .env")
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request(FLW_API + path, data=data, method=method,
                  headers={"Authorization": "Bearer " + FLW_SECRET_KEY,
                           "Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=25) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        raise RuntimeError("Flutterwave API error: " + detail[:500])
    except URLError as e:
        raise RuntimeError("Ntibashoboye kugera kuri Flutterwave: " + str(e.reason))

def credit_payment(tx_ref, flw_id):
    """Verify with Flutterwave, then credit the wallet once only."""
    with closing(db()) as c:
        p = c.execute("SELECT * FROM payments WHERE tx_ref=?", (tx_ref,)).fetchone()
    if not p:
        return False, "Payment ntibonetse."
    if p["status"] == "successful":
        return True, "Payment yari yamaze kwemezwa."
    verified = flw_call("GET", f"/transactions/{int(flw_id)}/verify")
    data = verified.get("data") or {}
    expected_amount = Decimal(p["amount"])
    try:
        paid_amount = Decimal(str(data.get("amount", "0")))
    except InvalidOperation:
        return False, "Amount yemejwe si yo."
    if (data.get("status") != "successful"
        or data.get("tx_ref") != tx_ref
        or data.get("currency") != p["currency"]
        or paid_amount < expected_amount):
        return False, "Flutterwave ntiyemeje ko payment yishyuwe neza."
    with closing(db()) as c:
        c.execute("BEGIN IMMEDIATE")
        current = c.execute("SELECT * FROM payments WHERE tx_ref=?", (tx_ref,)).fetchone()
        if current and current["status"] != "successful":
            row = c.execute("SELECT balance FROM wallets WHERE user_id=? AND currency=?",
                            (p["user_id"], p["currency"])).fetchone()
            old = Decimal(row["balance"]) if row else Decimal("0")
            new = old + expected_amount
            c.execute("""INSERT INTO wallets(user_id,currency,balance) VALUES(?,?,?)
                         ON CONFLICT(user_id,currency) DO UPDATE SET balance=excluded.balance""",
                      (p["user_id"], p["currency"], str(new)))
            c.execute("UPDATE payments SET status='successful', flw_id=? WHERE tx_ref=?",
                      (str(flw_id), tx_ref))
            c.execute("""INSERT INTO wallet_transactions
                         (user_id,kind,amount,currency,reference,created)
                         VALUES(?,?,?,?,?,?)""",
                      (p["user_id"], "deposit", str(expected_amount), p["currency"], tx_ref, time.time()))
        c.commit()
    return True, "Payment yemejwe. Amafaranga yongerewe kuri wallet."

@app.get("/")
def home():
    return render_template("index.html")

@app.post("/api/signup")
def signup():
    d = json_body()
    if not isinstance(d, dict): return jsonify(error="invalid_request"), 400
    email = str(d.get("email","")).strip().lower()
    password = str(d.get("password",""))
    role = "SELLER" if d.get("role") == "SELLER" else "BUYER"
    country = str(d.get("country","RW")).upper()[:2]
    phone = str(d.get("phone","")).strip()
    shop = " ".join(str(d.get("shop","")).split())[:80] if role == "SELLER" else ""
    if not EMAIL_RE.match(email): return jsonify(error="bad_email"), 400
    if len(password) < 8: return jsonify(error="bad_password"), 400
    if phone and not PHONE_RE.match(phone): return jsonify(error="bad_phone"), 400
    if role == "SELLER" and len(shop) < 2: return jsonify(error="bad_shop"), 400
    try:
        with closing(db()) as c:
            cur = c.execute("""INSERT INTO users(email,password_hash,country,phone,role,shop,created)
                               VALUES(?,?,?,?,?,?,?)""",
                            (email, generate_password_hash(password), country, phone, role, shop, time.time()))
            uid = cur.lastrowid
            for curr in ALLOWED_CURRENCIES:
                c.execute("INSERT OR IGNORE INTO wallets(user_id,currency,balance) VALUES(?,?,?)",
                          (uid,curr,"0"))
            c.commit()
            u = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    except sqlite3.IntegrityError:
        return jsonify(error="email_exists"), 409
    session.clear(); session["uid"] = u["id"]; session.permanent = True
    return jsonify(user=user_json(u)), 201

@app.post("/api/login")
def login():
    d = json_body()
    if not isinstance(d, dict): return jsonify(error="invalid_request"), 400
    email = str(d.get("identifier") or d.get("email") or "").strip().lower()
    with closing(db()) as c:
        u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u or not check_password_hash(u["password_hash"], str(d.get("password",""))):
        return jsonify(error="bad_login"), 401
    session.clear(); session["uid"] = u["id"]; session.permanent = True
    return jsonify(user=user_json(u))

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get("/api/me")
def me():
    u = current_user()
    return jsonify(user=user_json(u) if u else None)

@app.get("/api/wallet")
def wallet():
    u = current_user()
    if not u: return jsonify(error="login_required"), 401
    with closing(db()) as c:
        for curr in ALLOWED_CURRENCIES:
            c.execute("INSERT OR IGNORE INTO wallets(user_id,currency,balance) VALUES(?,?,?)",
                      (u["id"],curr,"0"))
        c.commit()
        rows = c.execute("SELECT currency,balance FROM wallets WHERE user_id=?", (u["id"],)).fetchall()
        history = c.execute("""SELECT kind,amount,currency,reference,created
                               FROM wallet_transactions WHERE user_id=? ORDER BY id DESC LIMIT 30""",
                            (u["id"],)).fetchall()
    return jsonify(balances={r["currency"]:r["balance"] for r in rows},
                   history=[dict(x) for x in history])

@app.post("/api/deposit")
def deposit():
    u = current_user()
    if not u: return jsonify(error="login_required"), 401
    d = json_body()
    if not isinstance(d, dict): return jsonify(error="invalid_request"), 400
    try: amount = money(d.get("amount"))
    except ValueError as e: return jsonify(error=str(e)), 400
    currency = str(d.get("currency","")).upper()
    if currency not in ALLOWED_CURRENCIES:
        return jsonify(error="currency_must_be_RWF_or_USD"), 400
    if not FLW_SECRET_KEY:
        return jsonify(error="FLW_SECRET_KEY_missing_check_env"), 503
    tx_ref = "SKY-" + uuid.uuid4().hex.upper()
    with closing(db()) as c:
        c.execute("""INSERT INTO payments(user_id,tx_ref,amount,currency,status,created)
                     VALUES(?,?,?,?,?,?)""",
                  (u["id"],tx_ref,str(amount),currency,"pending",time.time()))
        c.commit()
    payload = {
        "tx_ref": tx_ref,
        "amount": str(amount),
        "currency": currency,
        "redirect_url": SITE_URL + "/payment/callback",
        "customer": {"email": u["email"], "name": u["email"].split("@")[0],
                     "phonenumber": u["phone"] or ""},
        "customizations": {"title":"SKY ONLINE SHOP","description":"Wallet deposit"}
    }
    try:
        result = flw_call("POST","/payments",payload)
        link = (result.get("data") or {}).get("link")
        if result.get("status") != "success" or not link:
            raise RuntimeError("Flutterwave ntiyagaruye checkout link.")
        return jsonify(checkout_url=link, tx_ref=tx_ref)
    except Exception as e:
        with closing(db()) as c:
            c.execute("UPDATE payments SET status='failed' WHERE tx_ref=?", (tx_ref,))
            c.commit()
        return jsonify(error=str(e)), 502

@app.get("/payment/callback")
def payment_callback():
    tx_ref = request.args.get("tx_ref","")
    transaction_id = request.args.get("transaction_id","")
    status = request.args.get("status","")
    if status == "successful" and tx_ref and transaction_id:
        try:
            ok, message = credit_payment(tx_ref, transaction_id)
        except Exception as e:
            ok, message = False, str(e)
    else:
        ok, message = False, "Payment ntiyagenze neza cyangwa yarahagaritswe."
    return render_template("payment_result.html", ok=ok, message=message)

@app.post("/api/flw-webhook")
def flw_webhook():
    received = request.headers.get("verif-hash","")
    if not FLW_WEBHOOK_HASH or not secrets.compare_digest(received, FLW_WEBHOOK_HASH):
        return jsonify(error="unauthorized"), 401
    payload = request.get_json(silent=True) or {}
    data = payload.get("data") or {}
    tx_ref, flw_id = data.get("tx_ref"), data.get("id")
    if tx_ref and flw_id:
        try: credit_payment(str(tx_ref), str(flw_id))
        except Exception: app.logger.exception("Webhook verification failed")
    return jsonify(received=True), 200

@app.get("/api/products")
def products():
    u = current_user()
    if not u: return jsonify(error="login_required"), 401
    with closing(db()) as c:
        rows = c.execute("""SELECT p.*,u.shop,u.email seller_email
                            FROM products p JOIN users u ON u.id=p.seller_id
                            ORDER BY p.id DESC LIMIT 300""").fetchall()
    return jsonify(items=[{"id":r["id"],"title":r["title"],"description":r["description"],
        "price":r["price"],"currency":r["currency"],
        "image":("/uploads/"+r["image"]) if r["image"] else "",
        "shop":r["shop"],"seller_email":r["seller_email"],"mine":r["seller_id"]==u["id"]}
        for r in rows])

@app.post("/api/products")
def create_product():
    u = current_user()
    if not u: return jsonify(error="login_required"), 401
    if u["role"] != "SELLER": return jsonify(error="seller_only"), 403
    title = " ".join(request.form.get("title","").split())[:100]
    desc = request.form.get("description","").strip()[:1000]
    curr = request.form.get("currency","").upper()
    try: price = money(request.form.get("price"))
    except ValueError as e: return jsonify(error=str(e)), 400
    if len(title)<2 or curr not in ALLOWED_CURRENCIES:
        return jsonify(error="title_or_currency_invalid"), 400
    image_name = ""
    f = request.files.get("image")
    if f and f.filename:
        ext = secure_filename(f.filename).rsplit(".",1)[-1].lower()
        if ext not in ALLOWED_EXT: return jsonify(error="image_must_be_png_jpg_webp"), 400
        image_name = secrets.token_hex(16)+"."+ext
        f.save(os.path.join(UPLOAD_DIR,image_name))
    with closing(db()) as c:
        cur = c.execute("""INSERT INTO products(seller_id,title,description,price,currency,image,created)
                           VALUES(?,?,?,?,?,?,?)""",
                        (u["id"],title,desc,str(price),curr,image_name,time.time()))
        c.commit()
    return jsonify(id=cur.lastrowid), 201

@app.delete("/api/products/<int:pid>")
def delete_product(pid):
    u = current_user()
    if not u: return jsonify(error="login_required"), 401
    with closing(db()) as c:
        row = c.execute("SELECT image FROM products WHERE id=? AND seller_id=?", (pid,u["id"])).fetchone()
        if not row: return jsonify(error="not_found"), 404
        c.execute("DELETE FROM products WHERE id=?",(pid,)); c.commit()
    if row["image"]:
        try: os.remove(os.path.join(UPLOAD_DIR,row["image"]))
        except OSError: pass
    return jsonify(ok=True)

@app.post("/api/chat/send")
def chat_send():
    u=current_user()
    if not u: return jsonify(error="login_required"),401
    d=json_body()
    if not isinstance(d,dict): return jsonify(error="invalid_request"),400
    shop=" ".join(str(d.get("shop","")).split())[:80]
    body=str(d.get("body","")).strip()[:1000]
    if not shop or not body: return jsonify(error="shop_and_message_required"),400
    with closing(db()) as c:
        seller=c.execute("SELECT id FROM users WHERE role='SELLER' AND lower(shop)=lower(?)",(shop,)).fetchone()
        if not seller: return jsonify(error="shop_not_found"),404
        c.execute("""INSERT INTO messages(shop,buyer_email,sender_email,body,created)
                     VALUES(?,?,?,?,?)""",(shop,u["email"],u["email"],body,time.time()))
        c.commit()
    return jsonify(ok=True),201

@app.get("/api/chat/messages")
def chat_messages():
    u=current_user()
    if not u: return jsonify(error="login_required"),401
    shop=request.args.get("shop","")
    buyer=request.args.get("buyer",u["email"])
    with closing(db()) as c:
        rows=c.execute("""SELECT id,buyer_email,sender_email,body,created FROM messages
                          WHERE lower(shop)=lower(?) AND buyer_email=? ORDER BY id ASC LIMIT 200""",
                       (shop,buyer)).fetchall()
    return jsonify(messages=[dict(r) for r in rows])

@app.get("/uploads/<path:name>")
def uploaded(name):
    from flask import send_from_directory
    return send_from_directory(UPLOAD_DIR,name)

@app.get("/health")
def health():
    return jsonify(ok=True, payment_configured=bool(FLW_SECRET_KEY))

init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
