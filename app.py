import os
import io
import math
from io import BytesIO
from datetime import datetime, timedelta
from random import randint
import csv, zipfile, json

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

# ---- Env + Twilio
from dotenv import load_dotenv
load_dotenv()  # reads .env

from twilio.rest import Client

# ===== Twilio config (no hard-coded secrets) =====
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_VERIFY_SERVICE_SID = os.getenv("TWILIO_VERIFY_SERVICE_SID")  # required (you use Verify)
TWILIO_FROM = os.getenv("TWILIO_FROM")  # optional, only if you send SMS directly

missing = [k for k, v in {
    "TWILIO_ACCOUNT_SID": TWILIO_ACCOUNT_SID,
    "TWILIO_AUTH_TOKEN": TWILIO_AUTH_TOKEN,
    "TWILIO_VERIFY_SERVICE_SID": TWILIO_VERIFY_SERVICE_SID,
}.items() if not v]
if missing:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "dev-only-change-this")  # set real secret in production



# NOTE: db.py must define these
from db import (
    init_db, query, execute, add_order_event,
    create_password_reset_token, get_valid_reset_token, consume_reset_token,
    # Live GPS helpers
    save_delivery_location, get_latest_location_for_order,
    # Ratings + complaints helpers
    add_product_rating, add_store_rating,
    get_product_rating_summary, get_store_rating_summary,
    file_complaint, list_recent_complaints, update_complaint_status,
    # NEW admin helpers
    render_export_to_csv_zip_bytes, get_user_by_id, can_delete_user_hard, hard_delete_user,
    # NEW for atomic checkout + stock changes
    get_conn
)


# ---------------------------
# CONTEXT (globals to templates)
# ---------------------------
@app.context_processor
def inject_globals():
    return {
        "datetime": datetime,
        "service_area": session.get("service_area")  # {address,pincode,lat,lng} or None
    }

# ---- Footer links site-wide ----
FOOTER_LINKS = [
    {"label": "Privacy", "endpoint": "legal_privacy"},
    {"label": "Security", "endpoint": "legal_security"},
    {"label": "Terms of Service", "endpoint": "legal_terms"},
    {"label": "Help & Support", "endpoint": "legal_help"},
    {"label": "Report a Fraud", "endpoint": "legal_report_fraud"},
]
@app.context_processor
def inject_footer_links():
    return {"FOOTER_LINKS": FOOTER_LINKS}

# ----------------------
# DELIVERY CONFIG
# ----------------------
BASE_DELIVERY_FEE_INR = 40
DELIVERY_SURCHARGE_SLABS = [
    (0, 2, 0),
    (2, 5, 15),
    (5, 7, 25),
    (7, 10, 35),
]
MAX_DELIVERY_KM = 10.0

def haversine_km(lat1, lon1, lat2, lon2):
    if None in (lat1, lon1, lat2, lon2):
        return None
    R = 6371.0
    phi1 = math.radians(float(lat1))
    phi2 = math.radians(float(lat2))
    dphi = math.radians(float(lat2) - float(lat1))
    dlmb = math.radians(float(lon2) - float(lon1))
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

# ======================
# SERVICEABLE PINCODES
# ======================
def _ensure_serviceable_table():
    try:
        execute("""
            CREATE TABLE IF NOT EXISTS serviceable_pincodes (
              pincode TEXT PRIMARY KEY,
              label   TEXT
            )
        """)
    except Exception:
        pass

# Default seed (Aizawl)
SEED_PINS = [
    ("796001", "Aizawl"),
    ("796004", "Aizawl"),
    ("796005", "Aizawl"),
    ("796007", "Aizawl"),
    ("796008", "Aizawl"),
    ("796009", "Aizawl"),
    ("796012", "Aizawl"),
    ("796014", "Aizawl"),
    ("796015", "Aizawl"),
    ("796017", "Aizawl"),
]
def _seed_pincodes_if_empty():
    rows = query("SELECT COUNT(*) c FROM serviceable_pincodes")
    if rows and rows[0]["c"] == 0:
        for pc, label in SEED_PINS:
            try:
                execute("INSERT INTO serviceable_pincodes (pincode, label) VALUES (?,?)", (pc, label))
            except Exception:
                pass

with app.app_context():
    init_db()
    _ensure_serviceable_table()
    _seed_pincodes_if_empty()


def normalize_phone(phone: str) -> str:
    """
    Normalize to E.164. If user typed a 10-digit Indian number, prefix +91.
    If already starts with '+', return as-is.
    """
    p = (phone or "").strip().replace(" ", "")
    if p.startswith("+"):
        return p
    digits = "".join(ch for ch in p if ch.isdigit())
    if len(digits) == 10:
        return "+91" + digits
    return "+" + digits if digits and not digits.startswith("+") else digits


def _clean_pin(pin) -> str:
    """Keep digits only and trim spaces (handles '796001 ', 796001, etc.)."""
    if pin is None:
        return ""
    s = str(pin).strip()
    return "".join(ch for ch in s if ch.isdigit())

def get_serviceable_pincodes():
    rows = query("SELECT pincode FROM serviceable_pincodes ORDER BY pincode")
    return [r["pincode"] for r in rows]

def is_serviceable_pincode(pin: str) -> bool:
    clean_pin = _clean_pin(pin)
    if not clean_pin:
        return False
    # normalize every row from DB too
    pins = [_clean_pin(r) for r in get_serviceable_pincodes()]
    return clean_pin in set(pins)

@app.route("/api/service/pincodes")
def api_service_pincodes():
    return jsonify({"ok": True, "pincodes": get_serviceable_pincodes()})

# Store location data in session; front-end JS should call this after getting geolocation & pincode
@app.route("/api/location/set", methods=["POST"])
def api_location_set():
    data = request.get_json(silent=True) or {}
    address = (data.get("address") or "").strip()
    pincode_raw = data.get("pincode")
    lat = data.get("lat")
    lng = data.get("lng")

    pincode = _clean_pin(pincode_raw)
    if not pincode:
        return jsonify({"ok": False, "error": "no pincode"}), 400

    serviceable = is_serviceable_pincode(pincode)
    session["service_area"] = {
        "address": address or f"Pincode {pincode}",
        "pincode": pincode,
        "lat": lat,
        "lng": lng,
    }
    session.modified = True
    return jsonify({"ok": True, "serviceable": serviceable, "service_area": session["service_area"]})
@app.route("/api/location/clear", methods=["POST"])
def api_location_clear():
    session.pop("service_area", None)
    return jsonify({"ok": True})

# Convenience fallback: you can also GET/POST here if you don't want to use fetch().
# /detect-location?lat=..&lng=..&pincode=..&address=..
@app.route("/detect-location", methods=["GET", "POST"])
def detect_location():
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form or {}
        pincode = (data.get("pincode") or "").strip()
        address = (data.get("address") or "").strip()
        lat = data.get("lat")
        lng = data.get("lng")
    else:
        pincode = (request.args.get("pincode") or "").strip()
        address = (request.args.get("address") or "").strip()
        lat = request.args.get("lat")
        lng = request.args.get("lng")

    if not pincode:
        flash("Could not detect pincode.", "warning")
        return redirect(request.referrer or url_for("index"))

    session["service_area"] = {
        "address": address or f"Pincode {pincode}",
        "pincode": pincode,
        "lat": float(lat) if lat else None,
        "lng": float(lng) if lng else None,
    }
    session.modified = True
    if not is_serviceable_pincode(pincode):
        flash(f"Sorry, we currently serve select pincodes only. Your pincode {pincode} is not serviceable.", "warning")
    else:
        flash(f"Location set to {pincode}.", "success")
    return redirect(request.referrer or url_for("index"))

# ----------------------
# ADMIN: Manage serviceable pincodes
# ----------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    rows = query("SELECT * FROM users WHERE id=?", (uid,))
    return dict(rows[0]) if rows else None

def login_required(role=None):
    def deco(fn):
        @wraps(fn)
        def wrap(*a, **kw):
            u = current_user()
            if not u:
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            if role and u["role"] != role:
                flash("Access denied.", "danger")
                return redirect(url_for("index"))
            return fn(*a, **kw)
        return wrap
    return deco

@app.route("/admin/pincodes", methods=["GET"], endpoint="admin_pincodes")
@login_required(role='admin')
def admin_pincodes():
    pins = query("SELECT pincode, COALESCE(label,'') AS label FROM serviceable_pincodes ORDER BY pincode")
    return render_template("admin_pincodes.html", user=current_user(), pincodes=pins)

@app.route("/admin/pincodes/add", methods=["POST"], endpoint="admin_pincodes_add")
@login_required(role='admin')
def admin_pincodes_add():
    pin = (request.form.get("pincode") or "").strip()
    label = (request.form.get("label") or "").strip() or None
    if not pin.isdigit():
        flash("Enter a numeric pincode.", "warning")
        return redirect(url_for("admin_pincodes"))
    try:
        execute("INSERT INTO serviceable_pincodes (pincode, label) VALUES (?,?)", (pin, label))
        flash(f"Pincode {pin} added.", "success")
    except Exception:
        flash("Pincode already exists or DB error.", "danger")
    return redirect(url_for("admin_pincodes"))

@app.route("/admin/pincodes/<pin>/delete", methods=["POST"], endpoint="admin_pincodes_delete")
@login_required(role='admin')
def admin_pincodes_delete(pin):
    execute("DELETE FROM serviceable_pincodes WHERE pincode=?", (pin,))
    flash(f"Pincode {pin} removed.", "info")
    return redirect(url_for("admin_pincodes"))

# ----------------------
# MISC UTILS
# ----------------------
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTS = {"jpg","jpeg","png","webp"}
def allowed_file(filename): 
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTS

def _row_get(row, key, default=0):
    try:
        v = row[key]
        return default if v is None else v
    except Exception:
        return default

def order_total_payable(order_row):
    return float(_row_get(order_row, 'total_amount', 0)) + \
           float(_row_get(order_row, 'delivery_fee', 0)) + \
           float(_row_get(order_row, 'tip_amount', 0))

def ensure_admin_seed_password():
    rows = query("SELECT id,password_hash FROM users WHERE email=?", ("admin@chhimphei.local",))
    if rows and rows[0]["password_hash"] == "!!set_in_app!!":
        execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash("admin123"), rows[0]["id"]))

def send_sms(phone: str, message: str) -> bool:
    print(f"[DEV SMS] to={phone} :: {message}")
    return True

with app.app_context():
    ensure_admin_seed_password()

# =========================================================
# CUSTOMER CANCEL ORDER
# =========================================================
CANCELLABLE_STATUSES = {"PLACED", "CONFIRMED"}
def is_cancellable(status: str) -> bool:
    return status and status.upper() in CANCELLABLE_STATUSES

@app.route('/orders/<int:oid>/cancel', methods=['POST'])
@login_required()
def order_cancel(oid):
    u = current_user()
    rows = query("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, u["id"]))
    if not rows:
        flash("Order not found.", "danger")
        return redirect(url_for("orders"))

    order_row = dict(rows[0])
    if order_row["status"] not in CANCELLABLE_STATUSES:
        flash("This order can no longer be cancelled.", "warning")
        return redirect(url_for("order_track", oid=oid))

    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")

        cur.execute("SELECT status FROM orders WHERE id=? AND user_id=?", (oid, u["id"]))
        cur_status = cur.fetchone()
        if not cur_status or cur_status["status"] not in CANCELLABLE_STATUSES:
            conn.rollback()
            flash("This order can no longer be cancelled.", "warning")
            return redirect(url_for("order_track", oid=oid))

        cur.execute("SELECT product_id, weight_kg FROM order_items WHERE order_id=?", (oid,))
        for line in cur.fetchall():
            pid, w = int(line["product_id"]), float(line["weight_kg"] or 0)
            cur.execute("UPDATE products SET stock_kg = stock_kg + ? WHERE id=?", (w, pid))
            cur.execute("UPDATE products SET is_active=1 WHERE id=? AND stock_kg > 0", (pid,))

        now = datetime.utcnow().isoformat()
        cur.execute("""
            UPDATE orders
            SET status='CANCELLED',
                payment_status=CASE WHEN payment_status='PAID' THEN 'REFUNDED' ELSE payment_status END,
                delivery_partner_id=NULL
            WHERE id=?
        """, (oid,))
        cur.execute("""
            UPDATE transactions
            SET status=CASE
                WHEN status='PAID' THEN 'REFUNDED'
                ELSE 'VOID'
            END
            WHERE order_id=?
        """, (oid,))
        cur.execute("""
            INSERT INTO order_events (order_id, status, note, created_at)
            VALUES (?,?,?,?)
        """, (oid, "CANCELLED", "Cancelled by customer", now))

        conn.commit()
    except Exception as e:
        conn.rollback()
        flash(f"Could not cancel order: {e}", "danger")
        return redirect(url_for("order_track", oid=oid))
    finally:
        conn.close()

    flash("Order cancelled successfully.", "success")
    return redirect(url_for("orders"))

# ----------------------
# PUBLIC PAGES (with pincode gating)
# ----------------------
def _session_pin_is_serviceable():
    sa = session.get("service_area")
    pin = (sa.get("pincode").strip() if sa and sa.get("pincode") else "")
    return is_serviceable_pincode(pin), pin

@app.route('/')
def index():
    allow, pin = _session_pin_is_serviceable()
    if session.get("service_area") and not allow:
        flash(f"Sorry, we currently serve select pincodes only. Your pincode {pin or '(none)'} is not serviceable.", "warning")
        products = []
    else:
        products = query("""
            SELECT
              p.*,
              s.store_name,
              s.id AS store_id,
              (SELECT ROUND(AVG(r.rating), 1) FROM product_ratings r WHERE r.product_id = p.id) AS avg_rating,
              (SELECT COUNT(*) FROM product_ratings r2 WHERE r2.product_id = p.id) AS rating_count
            FROM products p
            JOIN stores s ON s.id = p.store_id
            WHERE p.is_active=1 AND p.stock_kg > 0
            ORDER BY p.created_at DESC
            LIMIT 12
        """)

    product_rating_map = {}
    store_rating_map = {}
    for p in products:
        product_rating_map[p["id"]] = {
            "avg": p["avg_rating"] if p["avg_rating"] is not None else 0,
            "count": p["rating_count"] if p["rating_count"] is not None else 0
        }
        sid = p["store_id"]
        if sid not in store_rating_map:
            store_rating_map[sid] = get_store_rating_summary(sid)

    return render_template(
        'index.html',
        user=current_user(),
        products=products,
        product_rating_map=product_rating_map,
        store_rating_map=store_rating_map
    )

# ----------------------
# LEGAL & HELP PAGES
# ----------------------
@app.route('/legal/privacy')
def legal_privacy():
    return render_template('legal/privacy.html', user=current_user())

@app.route('/legal/security')
def legal_security():
    return render_template('legal/security.html', user=current_user())

@app.route('/legal/terms')
def legal_terms():
    return render_template('legal/terms.html', user=current_user())

@app.route('/help')
def legal_help():
    return render_template('legal/help.html', user=current_user())

@app.route('/report-fraud')
def legal_report_fraud():
    return render_template('legal/report_fraud.html', user=current_user())

# ----------------------
# AUTH
# ----------------------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email','').lower().strip()
        password = request.form.get('password','')
        rows = query('SELECT * FROM users WHERE email=?', (email,))
        if not rows:
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

        u = rows[0]

        if not u['phone_verified']:
            flash('Please verify your mobile via OTP.', 'warning')
            session['otp_user_id'] = u['id']
            return redirect(url_for('verify_otp'))

        if not u['is_active'] and u['role'] != 'customer':
            flash('Your account awaits admin approval.', 'warning')
            return redirect(url_for('login'))

        if check_password_hash(u['password_hash'], password):
            session['user_id'] = u['id']
            flash('Welcome back!', 'success')
            if u['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif u['role'] == 'store':
                return redirect(url_for('store_dashboard'))
            elif u['role'] == 'delivery':
                return redirect(url_for('delivery_dashboard'))
            else:
                return redirect(url_for('index'))

        flash('Invalid credentials.', 'danger')

    return render_template('login.html')

# ---------- Forgot Password ----------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = request.form.get('identifier','').strip().lower()
        rows = query("SELECT * FROM users WHERE lower(email)=? OR phone=?", (identifier, identifier))
        if rows:
            u = dict(rows[0])
            token = create_password_reset_token(u['id'], minutes_valid=30)
            reset_link = url_for('reset_password', token=token, _external=True)
            print(f"[DEV RESET LINK] Send this to the user: {reset_link}")
            if u.get('phone'):
                try: send_sms(u['phone'], f"Reset your password: {reset_link}")
                except Exception: pass
        flash("If the account exists, a reset link has been sent.", "info")
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    row = get_valid_reset_token(token)
    if not row:
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_pw = request.form.get('password','')
        confirm = request.form.get('confirm','')
        if not new_pw or len(new_pw) < 6:
            flash("Password must be at least 6 characters.", "warning")
            return redirect(url_for('reset_password', token=token))
        if new_pw != confirm:
            flash("Passwords do not match.", "warning")
            return redirect(url_for('reset_password', token=token))
        pwd_hash = generate_password_hash(new_pw)
        execute("UPDATE users SET password_hash=? WHERE id=?", (pwd_hash, row['user_id']))
        consume_reset_token(token)
        flash("Your password has been reset. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# ---------- Register + OTP ----------
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = (request.form.get('name','') or '').strip()
        email = (request.form.get('email','') or '').lower().strip()
        phone = (request.form.get('phone','') or '').strip()
        password = request.form.get('password','') or ''

        # Basic validation to prevent silent failures
        if not name or not email or not phone or not password:
            flash('Please fill all fields.', 'warning')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'warning')
            return redirect(url_for('register'))

        # Normalize phone so Twilio gets +91XXXXXXXXXX (or +<countrycode>…)
        phone = normalize_phone(phone)

        try:
            uid = execute("""
                INSERT INTO users (name,email,phone,password_hash,role,phone_verified,is_active,created_at)
                VALUES (?,?,?,?, 'customer', 0, 0, ?)
            """, (name, email, phone, generate_password_hash(password), datetime.utcnow().isoformat()))
        except Exception:
            # Most common: UNIQUE(email) or UNIQUE(phone)
            flash('Email or phone already registered.', 'danger')
            return redirect(url_for('register'))

        # >>> Twilio Verify: send OTP via SMS <<<
        try:
            twilio_client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID).verifications.create(
                to=phone,
                channel='sms'
            )
        except Exception as e:
            # Roll back the user if you want, or just show error
            flash(f'Failed to send OTP: {e}', 'danger')
            return redirect(url_for('register'))

        session['otp_user_id'] = uid
        flash('OTP sent to your mobile. Please verify.', 'info')
        # ✅ Ensure redirect to verify_otp always happens
        return redirect(url_for('verify_otp'))

    return render_template('register.html')

@app.route('/verify-otp', methods=['GET','POST'])
def verify_otp():
    uid = session.get('otp_user_id')
    if not uid:
        flash('No OTP session. Please register or login first.', 'warning')
        return redirect(url_for('login'))

    # Get the phone saved for this user (should already be normalized)
    rows = query("SELECT phone FROM users WHERE id=?", (uid,))
    if not rows:
        flash("User not found.", "danger")
        return redirect(url_for('login'))
    phone = rows[0]['phone']

    if request.method == 'POST':
        code = (request.form.get('code','') or '').strip()
        if not code:
            flash('Please enter the OTP code.', 'warning')
            return redirect(url_for('verify_otp'))

        try:
            # Verify the code with Twilio Verify
            result = twilio_client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID).verification_checks.create(
                to=phone,
                code=code
            )
            if result.status == 'approved':
                execute('UPDATE users SET phone_verified=1 WHERE id=?', (uid,))
                flash('Mobile verified! Await admin approval to log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')
                return redirect(url_for('verify_otp'))
        except Exception as e:
            flash(f'OTP verification error: {e}', 'danger')
            return redirect(url_for('verify_otp'))

    # GET -> render the page with the form to enter the OTP
    return render_template('verify_otp.html')


@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    uid = session.get('otp_user_id')
    if not uid:
        return jsonify({'ok': False, 'msg': 'No OTP session.'}), 400

    u = query('SELECT phone FROM users WHERE id=?', (uid,))
    if not u:
        return jsonify({'ok': False, 'msg': 'User not found.'}), 404

    phone = u[0]['phone']
    try:
        # Re-trigger a verification via Twilio Verify
        twilio_client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID).verifications.create(
            to=phone,
            channel='sms'
        )
        return jsonify({'ok': True, 'msg': 'OTP resent.'})
    except Exception as e:
        return jsonify({'ok': False, 'msg': f'Failed to resend OTP: {e}'}), 500


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.','info')
    return redirect(url_for('index'))

# ----------------------
# CUSTOMER PROFILE + ADDRESSES
# ----------------------
@app.route("/profile", methods=["GET", "POST"])
@login_required()
def profile():
    u = current_user()
    if request.method == "POST":
        name = request.form.get("name","").strip()
        phone = request.form.get("phone","").strip()
        if name: execute("UPDATE users SET name=? WHERE id=?", (name, u["id"]))
        if phone: execute("UPDATE users SET phone=? WHERE id=?", (phone, u["id"]))
        flash("Profile updated.", "success")
        return redirect(url_for("profile"))

    addrs = query("SELECT * FROM addresses WHERE user_id=? ORDER BY is_default DESC, id DESC", (u["id"],))
    return render_template("profile.html", user=u, addresses=addrs)

@app.route("/profile/address/new", methods=["POST"])
@login_required()
def address_new():
    u = current_user()
    line1 = request.form.get("line1","").strip()
    line2 = request.form.get("line2","").strip()
    city = request.form.get("city","").strip()
    state = request.form.get("state","").strip()
    pincode = request.form.get("pincode","").strip()
    lat = request.form.get("latitude")
    lng = request.form.get("longitude")
    label = request.form.get("label","").strip() or "Home"
    is_def = 1 if request.form.get("is_default") == "1" else 0

    if not line1:
        flash("Address line 1 is required.", "warning")
        return redirect(url_for("profile"))

    if is_def:
        execute("UPDATE addresses SET is_default=0 WHERE user_id=?", (u["id"],))

    execute("""
        INSERT INTO addresses (user_id,label,line1,line2,city,state,pincode,latitude,longitude,is_default,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (u["id"], label, line1, line2, city, state, pincode,
          float(lat) if lat else None, float(lng) if lng else None,
          is_def, datetime.utcnow().isoformat()))
    flash("Address saved.", "success")
    return redirect(url_for("profile"))

@app.route("/profile/address/<int:aid>/delete", methods=["POST"])
@login_required()
def address_delete(aid):
    u = current_user()
    execute("DELETE FROM addresses WHERE id=? AND user_id=?", (aid, u["id"]))
    flash("Address deleted.", "info")
    return redirect(url_for("profile"))

@app.route("/profile/address/<int:aid>/default", methods=["POST"])
@login_required()
def address_set_default(aid):
    u = current_user()
    execute("UPDATE addresses SET is_default=0 WHERE user_id=?", (u["id"],))
    execute("UPDATE addresses SET is_default=1 WHERE id=? AND user_id=?", (aid, u["id"]))
    flash("Default address updated.", "success")
    return redirect(url_for("profile"))

@app.route("/api/profile/address/detect", methods=["POST"])
@login_required()
def api_address_detect():
    u = current_user()
    data = request.get_json(silent=True) or {}
    lat = data.get("latitude"); lng = data.get("longitude")
    if lat is None or lng is None:
        return jsonify({"ok": False, "msg": "No coordinates"}), 400
    aid = execute("""
        INSERT INTO addresses (user_id,label,line1,city,state,pincode,latitude,longitude,is_default,created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (u["id"], "Detected", "(Detected location)", "", "", "",
          float(lat), float(lng), 0, datetime.utcnow().isoformat()))
    return jsonify({"ok": True, "address_id": aid})

# ----------------------
# CATALOG + CART
# ----------------------
@app.route('/products')
def products():
    allow, pin = _session_pin_is_serviceable()
    if session.get("service_area") and not allow:
        flash(f"Sorry, we currently serve select pincodes only. Your pincode {pin or '(none)'} is not serviceable.", "warning")
        products = []
    else:
        products = query("""
        SELECT p.*, s.store_name
        FROM products p JOIN stores s ON s.id = p.store_id
        WHERE p.is_active=1 AND p.stock_kg > 0
        ORDER BY p.created_at DESC
    """)
    return render_template('products.html', products=products, user=current_user())

def get_or_create_cart(uid):
    rows = query('SELECT * FROM carts WHERE user_id=? ORDER BY id DESC LIMIT 1', (uid,))
    if rows: return rows[0]['id']
    return execute('INSERT INTO carts (user_id, created_at) VALUES (?,?)', (uid, datetime.utcnow().isoformat()))


@app.route('/cart')
@login_required()
def cart_page():
    u = current_user()
    cid = get_or_create_cart(u['id'])

    # IMPORTANT: return product_id and store_name so the template can link & show
    items = query('''
        SELECT
          ci.id                 AS cart_item_id,
          ci.weight_kg          AS weight_kg,
          p.id                  AS product_id,
          p.name                AS name,
          p.price_per_kg        AS price_per_kg,
          p.image_path          AS image_path,
          p.stock_kg            AS stock_kg,
          p.is_active           AS is_active,
          s.store_name          AS store_name
        FROM cart_items ci
        JOIN products p ON p.id = ci.product_id
        JOIN stores  s ON s.id = p.store_id
        WHERE ci.cart_id = ?
    ''', (cid,))

    total = sum([(row['weight_kg'] or 0) * (row['price_per_kg'] or 0) for row in items])

    return render_template('cart.html', items=items, total=total, user=u)



@app.route('/api/cart/add', methods=['POST'])
@login_required()
def api_cart_add():
    u = current_user()
    try:
        product_id = int(request.form.get('product_id'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Invalid product'}), 400

    try:
        weight_kg = float(request.form.get('weight_kg', '1') or 1)
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'error': 'Invalid weight'}), 400

    if weight_kg < 0.25:
        return jsonify({'ok': False, 'error': 'Minimum 0.25 kg'}), 400
    weight_kg = round(weight_kg, 2)

    prow = query("SELECT stock_kg, is_active FROM products WHERE id=?", (product_id,))
    if not prow:
        return jsonify({'ok': False, 'error': 'Product not found'}), 404

    stock = float(prow[0]['stock_kg'] or 0)
    active = int(prow[0]['is_active'] or 0)
    if active != 1 or stock <= 0:
        return jsonify({'ok': False, 'error': 'This item is sold out'}), 409
    if weight_kg > stock:
        return jsonify({'ok': False, 'error': f'Max available is {stock:.2f} kg'}), 409

    cid = get_or_create_cart(u['id'])
    rows = query('SELECT id FROM cart_items WHERE cart_id=? AND product_id=?', (cid, product_id))
    if rows:
        execute('UPDATE cart_items SET weight_kg=? WHERE id=?', (weight_kg, rows[0]['id']))
    else:
        execute('INSERT INTO cart_items (cart_id, product_id, weight_kg) VALUES (?,?,?)', (cid, product_id, weight_kg))

    return jsonify({'ok': True})

@app.route('/api/cart/remove', methods=['POST'])
@login_required()
def api_cart_remove():
    try:
        item_id = int(request.form.get('item_id'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'msg': 'Invalid item'}), 400

    execute('DELETE FROM cart_items WHERE id=?', (item_id,))
    return jsonify({'ok': True})

# ----------------------
# CHECKOUT + ORDERS
# ----------------------
@app.route('/checkout', methods=['GET','POST'])
@login_required()
def checkout():
    u = current_user()
    cid = get_or_create_cart(u['id'])
    items = query('''
        SELECT ci.product_id, ci.weight_kg, p.price_per_kg, p.store_id, p.stock_kg, p.is_active
        FROM cart_items ci JOIN products p ON p.id = ci.product_id
        WHERE ci.cart_id=?
    ''', (cid,))

    addresses = query("SELECT * FROM addresses WHERE user_id=? ORDER BY is_default DESC, id DESC", (u["id"],))

    if request.method == 'POST':
        if not items:
            flash('Your cart is empty.', 'warning')
            return redirect(url_for('cart_page'))

        for it in items:
            if int(it['is_active'] or 0) != 1 or float(it['stock_kg'] or 0) <= 0 or it['weight_kg'] > it['stock_kg']:
                flash('One or more items are sold out or reduced in stock.', 'danger')
                return redirect(url_for('cart_page'))

        addr_id = request.form.get("address_id")
        if not addr_id:
            flash("Please select a delivery address.", "warning")
            return redirect(url_for("checkout"))

        sel_rows = query("SELECT * FROM addresses WHERE id=? AND user_id=?", (addr_id, u["id"]))
        if not sel_rows:
            flash("Invalid address selected.", "danger")
            return redirect(url_for("checkout"))
        sel = sel_rows[0]

        sel_pin = (sel["pincode"] if "pincode" in sel.keys() and sel["pincode"] else "").strip()
        if not is_serviceable_pincode(sel_pin):
            flash(
                f"Sorry, we currently deliver only to allowed pincodes. "
                f"Your address pincode {sel_pin or '(none)'} is not serviceable.",
                "danger"
            )
            return redirect(url_for("checkout"))

        items_total = sum([it['weight_kg']*it['price_per_kg'] for it in items])
        store_id = items[0]['store_id']
        store_row = query("SELECT * FROM stores WHERE id=?", (store_id,))
        store = store_row[0] if store_row else None

        store_lat = store['latitude'] if store and 'latitude' in store.keys() else None
        store_lng = store['longitude'] if store and 'longitude' in store.keys() else None
        addr_lat = sel['latitude']; addr_lng = sel['longitude']
        km = haversine_km(store_lat, store_lng, addr_lat, addr_lng)

        if km is not None and km > MAX_DELIVERY_KM:
            flash(f"Delivery distance ({km:.1f} km) exceeds our limit of {MAX_DELIVERY_KM} km.", "danger")
            return redirect(url_for("checkout"))

        if km is None:
            delivery_fee = BASE_DELIVERY_FEE_INR
        else:
            extra = None
            for low, high, fee in DELIVERY_SURCHARGE_SLABS:
                last_high = DELIVERY_SURCHARGE_SLABS[-1][1]
                if (km >= low) and (km < high or high == last_high):
                    extra = fee; break
            if extra is None:
                flash("Delivery not available for this distance.", "danger")
                return redirect(url_for("checkout"))
            delivery_fee = BASE_DELIVERY_FEE_INR + extra

        tip_amount = request.form.get("tip_amount", "0").strip()
        try:
            tip_amount = float(tip_amount or 0)
        except ValueError:
            tip_amount = 0.0
        if tip_amount < 0: tip_amount = 0.0
        if tip_amount > 10000: tip_amount = 10000.0
        tip_amount = round(tip_amount, 2)

        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute("BEGIN IMMEDIATE")

            cur.execute('''
                SELECT ci.product_id, ci.weight_kg, p.price_per_kg, p.store_id, p.stock_kg, p.is_active
                FROM cart_items ci JOIN products p ON p.id = ci.product_id
                WHERE ci.cart_id=?
            ''', (cid,))
            tx_items = cur.fetchall()
            if not tx_items:
                conn.rollback()
                flash('Your cart is empty.', 'warning')
                return redirect(url_for('cart_page'))

            for it in tx_items:
                stock = float(it["stock_kg"] or 0)
                need  = float(it["weight_kg"] or 0)
                if int(it["is_active"] or 0) != 1 or stock <= 0 or need > stock:
                    conn.rollback()
                    flash('One or more items are sold out or reduced in stock.', 'danger')
                    return redirect(url_for('cart_page'))

            now = datetime.utcnow().isoformat()
            tx_items_total = sum(float(it["weight_kg"]) * float(it["price_per_kg"]) for it in tx_items)
            cur.execute('''
                INSERT INTO orders (user_id, store_id, total_amount, status, payment_status, created_at, delivery_fee, distance_km, tip_amount)
                VALUES (?,?,?,?,?,?,?,?,?)
            ''', (u['id'], store_id, tx_items_total, 'PLACED', 'PENDING', now,
                  float(delivery_fee), float(km) if km is not None else None, tip_amount))
            oid = cur.lastrowid

            for it in tx_items:
                pid = int(it["product_id"]); need = float(it["weight_kg"]); price = float(it["price_per_kg"])
                line_total = need * price
                cur.execute('''
                    INSERT INTO order_items (order_id, product_id, weight_kg, unit_price_per_kg, line_total)
                    VALUES (?,?,?,?,?)
                ''', (oid, pid, need, price, line_total))
                cur.execute("UPDATE products SET stock_kg = stock_kg - ? WHERE id=?", (need, pid))

            total_payable = tx_items_total + delivery_fee + tip_amount
            cur.execute("""
                INSERT INTO transactions (order_id, amount, payment_method, status, created_at)
                VALUES (?,?, 'COD','PENDING',?)
            """, (oid, total_payable, now))

            cur.execute("""
                INSERT INTO order_addresses (order_id,line1,line2,city,state,pincode,latitude,longitude,created_at)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (oid, sel["line1"], sel["line2"], sel["city"], sel["state"], sel["pincode"],
                  sel["latitude"], sel["longitude"], now))

            cur.execute("INSERT INTO order_events (order_id, status, note, created_at) VALUES (?,?,?,?)",
                        (oid, 'PLACED', '', now))

            cur.execute("DELETE FROM cart_items WHERE cart_id=?", (cid,))

            conn.commit()
        except Exception as e:
            conn.rollback()
            flash(f'Checkout failed: {e}', 'danger')
            return redirect(url_for('cart_page'))
        finally:
            conn.close()

        flash('Order placed! (COD).', 'success')
        return redirect(url_for('orders'))

    total = sum([it['weight_kg']*it['price_per_kg'] for it in items])
    return render_template('checkout.html', total=total, user=u, addresses=addresses)

# Orders list
@app.route("/orders", endpoint="orders")
@login_required()
def my_orders():
    u = current_user()
    orders = query('''
        SELECT o.*, s.store_name
        FROM orders o JOIN stores s ON s.id = o.store_id
        WHERE o.user_id=? ORDER BY o.created_at DESC
    ''', (u['id'],))
    return render_template('orders.html', orders=orders, user=u)

# ---------- Order tracking ----------
def get_order_full(oid, for_user_id=None):
    where = "o.id=?"
    params = [oid]
    if for_user_id is not None:
        where += " AND o.user_id=?"
        params.append(for_user_id)

    order = query(f"""
        SELECT o.*, s.store_name, dp.name AS delivery_partner_name
        FROM orders o
        JOIN stores s ON s.id = o.store_id
        LEFT JOIN users dp ON dp.id = o.delivery_partner_id
        WHERE {where}
        LIMIT 1
    """, tuple(params))
    if not order:
        return None

    items = query("""
        SELECT oi.*, p.name, p.image_path, p.price_per_kg
        FROM order_items oi
        JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id=?
    """, (oid,))

    addr = query("SELECT * FROM order_addresses WHERE order_id=? ORDER BY id DESC LIMIT 1", (oid,))
    events = query("SELECT status, note, created_at FROM order_events WHERE order_id=? ORDER BY id ASC", (oid,))

    return {
        "order": dict(order[0]),
        "items": [dict(i) for i in items],
        "address": dict(addr[0]) if addr else None,
        "events": [dict(e) for e in events],
    }

@app.route('/about')
def about():
    """
    About Us page for Chhimphei Women Poultry Producer Company Limited
    """
    company_info = {
        "name": "Chhimphei Women Poultry Producer Company Limited",
        "year": 2018,
        "location": "Melriat, Aizawl, Mizoram",
        "fssai": "21825102002418",
        "phone": "8132831406",
        "website": "chhimphei.com",
        "supported_by": "Mizoram State Rural Livelihood Mission (MzSRLM)",
    }
    return render_template('about.html', info=company_info)

@app.route("/orders/<int:oid>")
@login_required()
def order_track(oid):
    u = current_user()
    data = get_order_full(oid, for_user_id=u["id"] if u["role"] == "customer" else None)
    if not data:
        flash("Order not found.", "danger")
        return redirect(url_for("orders"))
    return render_template("order_track.html", user=u, **data)

# ---------- Feedback ----------
def _clamp_rating(val):
    try:
        v = int(val)
    except (TypeError, ValueError):
        return None
    if v < 1 or v > 5:
        return None
    return v

@app.route("/orders/<int:oid>/feedback", methods=["POST"])
@login_required()
def order_feedback(oid):
    u = current_user()
    own = query("SELECT * FROM orders WHERE id=? AND user_id=?", (oid, u["id"]))
    if not own:
        flash("Order not found.", "danger")
        return redirect(url_for('orders'))
    order_row = dict(own[0])

    if order_row["status"] != "DELIVERED":
        flash("You can submit feedback only after delivery.", "warning")
        return redirect(url_for("order_track", oid=oid))

    if request.form.get("received_confirm") != "1":
        flash("Please confirm that you received your items.", "warning")
        return redirect(url_for("order_track", oid=oid))

    order_items = query("""
        SELECT oi.product_id, p.name
        FROM order_items oi
        JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id=?
    """, (oid,))

    store_rating = _clamp_rating(request.form.get("store_rating"))
    if store_rating:
        add_store_rating(u['id'], order_row["store_id"], store_rating, request.form.get("store_comment","").strip() or None)

    if order_row.get("delivery_partner_id"):
        delivery_rating = _clamp_rating(request.form.get("delivery_rating"))
        if delivery_rating:
            execute("""
                CREATE TABLE IF NOT EXISTS delivery_ratings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    order_id INTEGER NOT NULL,
                    delivery_partner_id INTEGER NOT NULL,
                    rating INTEGER NOT NULL,
                    comment TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            execute("""
                INSERT INTO delivery_ratings (user_id, order_id, delivery_partner_id, rating, comment, created_at)
                VALUES (?,?,?,?,?,?)
            """, (u["id"], oid, order_row["delivery_partner_id"], delivery_rating,
                  (request.form.get("delivery_comment") or "").strip() or None, datetime.utcnow().isoformat()))

    for it in order_items:
        pid = it["product_id"]
        r = _clamp_rating(request.form.get(f"product_rating_{pid}"))
        c = (request.form.get(f"product_comment_{pid}") or "").strip() or None
        if r:
            add_product_rating(u['id'], pid, r, c)

    title = (request.form.get("complaint_title") or "").strip()
    desc  = (request.form.get("complaint_description") or "").strip()
    image = request.files.get("complaint_image")
    image_path = None
    if image and image.filename and allowed_file(image.filename):
        fn = secure_filename(image.filename)
        save_as = datetime.utcnow().strftime("%Y%m%d%H%M%S_") + fn
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        image.save(os.path.join(app.config["UPLOAD_FOLDER"], save_as))
        image_path = f"uploads/{save_as}"

    if title or desc or image_path:
        msg = f"{title}\n{desc}".strip()
        try:
            file_complaint(u['id'], 'store', order_row["store_id"], msg, oid, image_path=image_path, title=title or None)
        except Exception:
            pass
        if order_row.get("delivery_partner_id"):
            try:
                file_complaint(u['id'], 'delivery', int(order_row["delivery_partner_id"]), msg, oid, image_path=image_path, title=title or None)
            except Exception:
                pass

    flash("Thanks for your feedback!", "success")
    return redirect(url_for("order_track", oid=oid))

# ----------------------
# DELIVERY
# ----------------------
@app.route('/delivery')
@login_required(role='delivery')
def delivery_dashboard():
    u = current_user()
    orders = query('''
    SELECT o.*, s.store_name,
           cu.name  AS customer_name,
           cu.phone AS customer_phone,
           oa.line1 AS addr_line1, oa.line2 AS addr_line2, oa.city AS addr_city,
           oa.state AS addr_state, oa.pincode AS addr_pincode, oa.latitude AS addr_lat, oa.longitude AS addr_lng
    FROM orders o
    JOIN stores s ON s.id = o.store_id
    JOIN users  cu ON cu.id = o.user_id
    LEFT JOIN order_addresses oa ON oa.order_id = o.id
    WHERE o.delivery_partner_id = ? OR o.delivery_partner_id IS NULL
    GROUP BY o.id
    ORDER BY o.created_at DESC
''', (u['id'],))
    return render_template('delivery_dashboard.html', user=u, orders=orders)

@app.route('/delivery/order/<int:oid>/assign', methods=['POST'])
@login_required(role='delivery')
def delivery_assign(oid):
    u = current_user()
    execute('UPDATE orders SET delivery_partner_id=? WHERE id=?', (u['id'], oid))
    add_order_event(oid, 'ASSIGNED_TO_DELIVERY')
    flash('Order assigned to you.','success')
    return redirect(url_for('delivery_dashboard'))

@app.route('/delivery/order/<int:oid>/status', methods=['POST'])
@login_required(role='delivery')
def delivery_status(oid):
    new_status = request.form.get('status', 'OUT_FOR_DELIVERY').upper()

    if new_status == 'DELIVERED':
        cod_received = request.form.get('cod_received')
        if cod_received != '1':
            flash('Please confirm that payment (COD) has been received before marking Delivered.', 'warning')
            return redirect(url_for('delivery_dashboard'))

        execute('UPDATE orders SET status=? WHERE id=?', (new_status, oid))
        add_order_event(oid, new_status, "COD received")
        execute("UPDATE transactions SET status='PAID' WHERE order_id=?", (oid,))
        execute("UPDATE orders SET payment_status='PAID' WHERE id=?", (oid,))
        flash('Delivery completed and payment confirmed.','success')
        return redirect(url_for('delivery_dashboard'))

    execute('UPDATE orders SET status=? WHERE id=?', (new_status, oid))
    add_order_event(oid, new_status)
    flash('Delivery status updated.','success')
    return redirect(url_for('delivery_dashboard'))

# ----------------------
# DELIVERY API — Customer polls rider location
# ----------------------
@app.route('/delivery/api/location', methods=['POST'])
@login_required(role='delivery')
def delivery_update_location():
    data = request.get_json(silent=True) or {}
    try:
        lat = float(data.get('latitude')); lng = float(data.get('longitude'))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "latitude/longitude required"}), 400

    oid = data.get('order_id')
    heading = data.get('heading'); speed = data.get('speed')

    if oid:
        chk = query("SELECT id FROM orders WHERE id=?", (oid,))
        if not chk:
            return jsonify({"ok": False, "error": "order not found"}), 404

    save_delivery_location(current_user()["id"], lat, lng, oid, heading, speed)
    return jsonify({"ok": True})

# --- Product detail with ratings ---
@app.route('/product/<int:pid>')
def product_detail(pid):
    rows = query("""
        SELECT p.*, s.store_name, s.id AS store_id
        FROM products p
        JOIN stores s ON s.id = p.store_id
        WHERE p.id=? LIMIT 1
    """, (pid,))
    if not rows:
        flash("Product not found.","warning")
        return redirect(url_for('products'))

    p = dict(rows[0])
    u = current_user()
    is_staff = bool(u and (u.get("role") in ("admin","store")))
    if not is_staff and (int(p.get("is_active") or 0) != 1 or float(p.get("stock_kg") or 0) <= 0):
        abort(404)

    rating_summary = get_product_rating_summary(pid)
    reviews = query("""
        SELECT pr.rating, pr.comment, pr.created_at, u.name AS reviewer_name
        FROM product_ratings pr
        JOIN users u ON u.id = pr.user_id
        WHERE pr.product_id=?
        ORDER BY pr.created_at DESC
    """, (pid,))

    return render_template(
        'product.html',
        user=u,
        product=p,
        rating=rating_summary,
        reviews=reviews
    )

@app.route('/api/delivery/orders/<int:oid>/location', methods=['GET'])
@login_required()
def delivery_api_get_latest(oid):
    row = query(
        "SELECT latitude, longitude, recorded_at AS updated_at "
        "FROM delivery_locations WHERE order_id=? "
        "ORDER BY id DESC LIMIT 1",
        (oid,)
    )
    if not row:
        return jsonify({"ok": True, "has_location": False})
    r = row[0]
    return jsonify({"ok": True, "has_location": True, "data": {
        "latitude": r["latitude"],
        "longitude": r["longitude"],
        "updated_at": r["updated_at"]
    }})

# ----------- ALERTS -----------
@app.route('/api/alerts/store', methods=['GET'])
@login_required(role='store')
def api_alerts_store():
    since = request.args.get('since') or (datetime.utcnow() - timedelta(minutes=2)).isoformat()
    u = current_user()
    srow = query('SELECT id FROM stores WHERE user_id=?', (u['id'],))
    if not srow:
        return jsonify({'ok': True, 'new': []})
    sid = srow[0]['id']

    rows = query("""
      SELECT o.id, o.created_at, o.total_amount, o.delivery_fee, o.tip_amount
      FROM orders o
      WHERE o.store_id=? AND o.created_at>?
      ORDER BY o.created_at DESC
    """, (sid, since))

    new_items = []
    for r in rows:
        total_payable = order_total_payable(r)
        new_items.append({'order_id': r['id'], 'created_at': r['created_at'], 'total_payable': total_payable})
    return jsonify({'ok': True, 'new': new_items})

@app.route('/api/alerts/delivery', methods=['GET'])
@login_required(role='delivery')
def api_alerts_delivery():
    since = request.args.get('since') or (datetime.utcnow() - timedelta(minutes=2)).isoformat()
    rows = query("""
      SELECT o.id, o.created_at, o.total_amount, o.delivery_fee, o.tip_amount
      FROM orders o
      WHERE (o.delivery_partner_id IS NULL) AND o.created_at>?
      ORDER BY o.created_at DESC
    """, (since,))
    new_items = []
    for r in rows:
        total_payable = order_total_payable(r)
        new_items.append({'order_id': r['id'], 'created_at': r['created_at'], 'total_payable': total_payable})
    return jsonify({'ok': True, 'new': new_items})

@app.route('/api/store/orders/<int:oid>', methods=['GET'])
@login_required(role='store')
def api_store_order_detail(oid):
    u = current_user()
    srow = query('SELECT id FROM stores WHERE user_id=?', (u['id'],))
    if not srow:
        return jsonify({'ok': False, 'error': 'store not found'}), 404
    sid = srow[0]['id']

    rows = query('''
        SELECT o.*, 
               u.name  AS customer_name,
               u.phone AS customer_phone,
               oa.line1 AS addr_line1, oa.line2 AS addr_line2, oa.city AS addr_city,
               oa.state AS addr_state, oa.pincode AS addr_pincode, oa.latitude AS addr_lat, oa.longitude AS addr_lng
        FROM orders o
        JOIN users u ON u.id = o.user_id
        LEFT JOIN order_addresses oa ON oa.order_id = o.id
        WHERE o.id=? AND o.store_id=?
        GROUP BY o.id
        LIMIT 1
    ''', (oid, sid))
    if not rows:
        return jsonify({'ok': False, 'error': 'not found'}), 404

    o = dict(rows[0])
    return jsonify({
        'ok': True,
        'order': {
            'id': o['id'],
            'created_at': o['created_at'],
            'status': o['status'],
            'payment_status': o['payment_status'],
            'total_amount': float(o.get('total_amount') or 0.0),
            'delivery_fee': float(o.get('delivery_fee') or 0.0),
            'tip_amount': float(o.get('tip_amount') or 0.0),
            'customer_name': o.get('customer_name'),
            'customer_phone': o.get('customer_phone'),
            'addr_line1': o.get('addr_line1'),
            'addr_line2': o.get('addr_line2'),
            'addr_city': o.get('addr_city'),
            'addr_state': o.get('addr_state'),
            'addr_pincode': o.get('addr_pincode'),
            'addr_lat': o.get('addr_lat'),
            'addr_lng': o.get('addr_lng'),
        }
    })

# ======================
# UNIVERSAL SEARCH
# ======================
@app.route("/search")
def search():
    q = (request.args.get("q", "") or "").strip()
    user = current_user()

    products = []
    stores = []

    if q:
        like = f"%{q.lower()}%"
        products = query("""
            SELECT p.*, s.store_name, s.id AS store_id
            FROM products p
            JOIN stores s ON s.id = p.store_id
            WHERE p.is_active=1 AND p.stock_kg > 0
              AND (lower(p.name) LIKE ? OR lower(s.store_name) LIKE ?)
            ORDER BY p.created_at DESC
            LIMIT 50
        """, (like, like))

        stores = query("""
            SELECT s.id, s.store_name, s.address,
                   COUNT(p.id) AS product_count
            FROM stores s
            JOIN products p ON p.store_id = s.id
            WHERE p.is_active=1 AND p.stock_kg > 0
              AND (lower(s.store_name) LIKE ?)
            GROUP BY s.id
            ORDER BY product_count DESC
            LIMIT 30
        """, (like,))

    return render_template("search.html", user=user, q=q, products=products, stores=stores)

# ======================
# STORE CATALOG PAGE (also gated)
# ======================
@app.route("/stores/<int:sid>")
def store_catalog(sid):
    user = current_user()
    srows = query("SELECT id, store_name, address FROM stores WHERE id=?", (sid,))
    if not srows:
        flash("Store not found.", "warning")
        return redirect(url_for("products"))
    store = dict(srows[0])

    allow, pin = _session_pin_is_serviceable()
    if session.get("service_area") and not allow:
        flash(f"Sorry, we currently serve select pincodes only. Your pincode {pin or '(none)'} is not serviceable.", "warning")
        products = []
    else:
        products = query("""
        SELECT p.*, s.store_name
        FROM products p
        JOIN stores s ON s.id = p.store_id
        WHERE p.store_id=? AND p.is_active=1 AND p.stock_kg > 0
        ORDER BY p.created_at DESC
    """, (sid,))

    return render_template("store_catalog.html", user=user, store=store, products=products)

@app.route("/api/search/suggest")
def api_search_suggest():
    q = (request.args.get("q","") or "").strip().lower()
    if not q:
        return jsonify({"ok": True, "products": [], "stores": []})
    like = f"%{q}%"
    pro = query("""
      SELECT p.id, p.name, s.store_name
      FROM products p JOIN stores s ON s.id=p.store_id
      WHERE p.is_active=1 AND p.stock_kg>0 AND (lower(p.name) LIKE ?)
      ORDER BY p.created_at DESC LIMIT 8
    """, (like,))
    sto = query("""
      SELECT id, store_name FROM stores
      WHERE lower(store_name) LIKE ? LIMIT 6
    """, (like,))
    return jsonify({
        "ok": True,
        "products": [dict(r) for r in pro],
        "stores": [dict(r) for r in sto]
    })

# ----------------------
# Ratings routes — disabled (from feedback only)
# ----------------------
@app.route('/rate/product/<int:pid>', methods=['POST'])
@login_required()
def rate_product_disabled(pid):
    flash('Please rate from the order page after your delivery is completed.', 'info')
    return redirect(request.referrer or url_for('orders'))

@app.route('/rate/store/<int:sid>', methods=['POST'])
@login_required()
def rate_store_disabled(sid):
    flash('Please rate from the order page after your delivery is completed.', 'info')
    return redirect(request.referrer or url_for('orders'))

@app.route('/api/ratings/product/<int:pid>')
def api_ratings_product(pid):
    s = get_product_rating_summary(pid)
    return jsonify({"ok": True, "avg": s["avg"], "count": s["count"]})

@app.route('/api/ratings/store/<int:sid>')
def api_ratings_store(sid):
    s = get_store_rating_summary(sid)
    return jsonify({"ok": True, "avg": s["avg"], "count": s["count"]})

# ----------------------
# Complaints
# ----------------------
@app.route('/complaints', methods=['POST'])
@login_required()
def complaints_create():
    u = current_user()
    target_type = (request.form.get('target_type','') or '').lower()
    target_id = int(request.form.get('target_id','0') or 0)
    message = (request.form.get('message','') or '').strip()
    order_id = request.form.get('order_id')
    order_id = int(order_id) if order_id else None
    title = (request.form.get('title') or '').strip() or None

    if target_type not in ('store','delivery','product') or not target_id or not message:
        flash('Please provide valid complaint details.','warning')
        return redirect(request.referrer or url_for('index'))

    image_path = None
    f = request.files.get('image')
    if f and f.filename:
        fn = secure_filename(f.filename)
        save_as = datetime.utcnow().strftime("%Y%m%d%H%M%S_") + fn
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        f.save(os.path.join(app.config["UPLOAD_FOLDER"], save_as))
        image_path = f"uploads/{save_as}"

    try:
        file_complaint(u['id'], target_type, target_id, message, order_id, image_path=image_path, title=title)
        flash('Complaint submitted. We’ll review it shortly.','success')
    except Exception as e:
        flash(f'Could not submit complaint: {e}','danger')
    return redirect(request.referrer or url_for('index'))

# ----------------------
# ADMIN
# ----------------------
def table_has_columns(table, columns):
    try:
        cols = [row['name'] for row in query(f"PRAGMA table_info({table})")]
        return all(col in cols for col in columns)
    except Exception:
        return False

def _csv_from_rows(rows):
    if not rows:
        return [], []
    dict_rows = [dict(r) if not isinstance(r, dict) else r for r in rows]
    keys = set()
    for r in dict_rows:
        keys.update(r.keys())
    fieldnames = sorted(keys)
    return fieldnames, dict_rows

def _zip_add_csv(zf, name, rows):
    fieldnames, dict_rows = _csv_from_rows(rows)
    buf = io.StringIO()
    if fieldnames:
        w = csv.DictWriter(buf, fieldnames=fieldnames)
        w.writeheader()
        for r in dict_rows:
            row = {k: r.get(k) for k in fieldnames}
            w.writerow(row)
    zf.writestr(name, buf.getvalue())

def _zip_add_json(zf, name, obj):
    zf.writestr(name, json.dumps(obj, indent=2, default=str))

@app.route('/admin/dashboard')
@login_required(role='admin')
def admin_dashboard():
    metrics = {
        'users': query('SELECT COUNT(*) c FROM users')[0]['c'],
        'stores': query('SELECT COUNT(*) c FROM stores')[0]['c'],
        'products': query('SELECT COUNT(*) c FROM products')[0]['c'],
        'orders': query('SELECT COUNT(*) c FROM orders')[0]['c'],
        'gmv': query('SELECT COALESCE(SUM(total_amount),0) amt FROM orders')[0]['amt'],
    }

    by_store = query('''
        SELECT s.id AS store_id, s.store_name,
               COUNT(o.id) AS orders,
               COALESCE(SUM(o.total_amount),0) AS revenue
        FROM stores s
        LEFT JOIN orders o ON o.store_id = s.id
        GROUP BY s.id
        ORDER BY revenue DESC
    ''')

    top_store_complaints = []
    top_delivery_complaints = []

    legacy_complaints = table_has_columns('complaints', ['target_type', 'target_id', 'message'])
    new_store_col = table_has_columns('complaints', ['store_id'])
    new_delivery_col = table_has_columns('complaints', ['delivery_partner_id'])

    if new_store_col:
        top_store_complaints = query('''
            SELECT s.id AS store_id, s.store_name, COUNT(*) AS cnt
            FROM complaints c
            JOIN stores s ON s.id = c.store_id
            GROUP BY s.id
            ORDER BY cnt DESC
            LIMIT 5
        ''')
    elif legacy_complaints:
        top_store_complaints = query('''
            SELECT s.id AS store_id, s.store_name, COUNT(*) AS cnt
            FROM complaints c
            JOIN stores s ON s.id = c.target_id
            WHERE c.target_type = 'store'
            GROUP BY s.id
            ORDER BY cnt DESC
            LIMIT 5
        ''')

    if new_delivery_col:
        top_delivery_complaints = query('''
            SELECT u.id AS delivery_id, u.name, COUNT(*) AS cnt
            FROM complaints c
            JOIN users u ON u.id = c.delivery_partner_id
            WHERE u.role = 'delivery'
            GROUP BY u.id
            ORDER BY cnt DESC
            LIMIT 5
        ''')
    elif legacy_complaints:
        top_delivery_complaints = query('''
            SELECT u.id AS delivery_id, u.name, COUNT(*) AS cnt
            FROM complaints c
            JOIN users u ON u.id = c.target_id
            WHERE c.target_type = 'delivery' AND u.role = 'delivery'
            GROUP BY u.id
            ORDER BY cnt DESC
            LIMIT 5
        ''')

    # NOTE: Add in admin_dashboard.html: <a href="{{ url_for('admin_pincodes') }}">Manage Pincodes</a>
    return render_template(
        'admin_dashboard.html',
        user=current_user(),
        metrics=metrics,
        by_store=by_store,
        top_store_complaints=top_store_complaints,
        top_delivery_complaints=top_delivery_complaints
    )

@app.route('/admin/approvals')
@login_required(role='admin')
def admin_approvals():
    flash('Approval feature under development.', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/create-store', methods=['GET','POST'])
@login_required(role='admin')
def admin_create_store():
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        email = request.form.get('email','').lower().strip()
        phone = request.form.get('phone','').strip()
        password = request.form.get('password','')
        store_name = request.form.get('store_name','').strip()
        address = request.form.get('address','').strip()
        uid = execute("""INSERT INTO users (name,email,phone,password_hash,role,phone_verified,is_active,created_at)
                        VALUES (?,?,?,?, 'store', 1, 1, ?)""",
                        (name, email, phone, generate_password_hash(password), datetime.utcnow().isoformat()))
        execute("INSERT INTO stores (user_id, store_name, address, created_at) VALUES (?,?,?,?)",
                (uid, store_name, address, datetime.utcnow().isoformat()))
        flash('Store created.','success'); return redirect(url_for('admin_create_store'))
    return render_template('admin_create_store.html', user=current_user())

@app.route('/admin/create-delivery', methods=['GET','POST'])
@login_required(role='admin')
def admin_create_delivery():
    if request.method == 'POST':
        name = request.form.get('name','').strip()
        email = request.form.get('email','').lower().strip()
        phone = request.form.get('phone','').strip()
        password = request.form.get('password','')
        execute("""INSERT INTO users (name,email,phone,password_hash,role,phone_verified,is_active,created_at)
                    VALUES (?,?,?,?, 'delivery', 1, 1, ?)""",
                (name, email, phone, generate_password_hash(password), datetime.utcnow().isoformat()))
        flash('Delivery partner created.','success'); return redirect(url_for('admin_create_delivery'))
    return render_template('admin_create_delivery.html', user=current_user())

# ---- Enable/Disable/Delete/Export per-user ----
@app.route('/admin/users/<int:uid>/enable', methods=['POST'])
@login_required(role='admin')
def admin_user_enable(uid):
    execute("UPDATE users SET is_active=1 WHERE id=?", (uid,))
    flash('User activated.', 'success')
    return redirect(request.referrer or url_for('admin_users'))

@app.route('/admin/transactions.csv')
@login_required(role='admin')
def admin_transactions_csv():
    rows = query('''
        SELECT t.id as txn_id, t.created_at, o.id as order_id, o.total_amount, t.amount, t.status
        FROM transactions t JOIN orders o ON o.id = t.order_id
        ORDER BY t.created_at DESC
    ''')
    csv_lines = ['txn_id,created_at,order_id,total_amount,amount,status']
    for r in rows:
        csv_lines.append(f"{r['txn_id']},{r['created_at']},{r['order_id']},{r['total_amount']},{r['amount']},{r['status']}")
    data = "\n".join(csv_lines).encode('utf-8')
    return send_file(io.BytesIO(data), mimetype='text/csv', as_attachment=True, download_name='transactions.csv')

@app.route('/admin/users/<int:uid>/transactions.csv')
@login_required(role='admin')
def admin_user_transactions_csv(uid):
    user_orders = query("SELECT id FROM orders WHERE user_id=? OR delivery_partner_id=?", (uid, uid))
    srows = query("SELECT id FROM stores WHERE user_id=?", (uid,))
    if srows:
        sids = [r['id'] for r in srows]
        ph = ','.join('?' * len(sids))
        more = query(f"SELECT id FROM orders WHERE store_id IN ({ph})", tuple(sids))
        user_orders += more
    if not user_orders:
        return send_file(io.BytesIO(b"txn_id,created_at,order_id,amount,status\n"), mimetype='text/csv', as_attachment=True, download_name=f'user_{uid}_transactions.csv')

    oids = [r['id'] for r in user_orders]
    ph = ','.join('?' * len(oids))
    rows = query(f"""
        SELECT t.id as txn_id, t.created_at, t.order_id, t.amount, t.status
        FROM transactions t
        WHERE t.order_id IN ({ph})
        ORDER BY t.created_at DESC
    """, tuple(oids))

    csv_lines = ['txn_id,created_at,order_id,amount,status']
    for r in rows:
        csv_lines.append(f"{r['txn_id']},{r['created_at']},{r['order_id']},{r['amount']},{r['status']}")
    data = "\n".join(csv_lines).encode('utf-8')
    return send_file(io.BytesIO(data), mimetype='text/csv', as_attachment=True, download_name=f'user_{uid}_transactions.csv')

@app.route('/admin/users/<int:uid>/export', methods=['GET'])
@login_required(role='admin')
def admin_user_export(uid):
    u = get_user_by_id(uid)
    if not u:
        flash('User not found.','warning')
        return redirect(url_for('admin_users'))
    try:
        data = render_export_to_csv_zip_bytes(uid)
    except Exception as e:
        flash(f'Failed to prepare export: {e}', 'danger')
        return redirect(url_for('admin_users'))
    fn = f"user_{uid}_export_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.zip"
    return send_file(BytesIO(data), mimetype='application/zip', as_attachment=True, download_name=fn)

@app.route('/admin/users/<int:uid>/export.zip', methods=['GET'])
@login_required(role='admin')
def admin_user_export_zip(uid):
    return admin_user_export(uid)

@app.route('/admin/users/<int:uid>/delete-hard', methods=['POST'])
@login_required(role='admin')
def admin_user_delete_hard(uid):
    ok, reason = can_delete_user_hard(uid)
    if not ok:
        flash(f'Cannot hard-delete: {reason}. The account should remain or be disabled.', 'warning')
        return redirect(request.referrer or url_for('admin_users'))
    try:
        if hard_delete_user(uid):
            flash('User hard-deleted.','success')
        else:
            flash('Hard delete failed.','danger')
    except Exception as e:
        flash(f'Hard delete failed: {e}','danger')
    return redirect(request.referrer or url_for('admin_users'))

@app.route('/admin/complaints')
@login_required(role='admin')
def admin_complaints():
    complaints = list_recent_complaints(limit=200)
    return render_template('admin_complaints.html', user=current_user(), complaints=complaints)

@app.route('/admin/complaints/<int:cid>/status', methods=['POST'])
@login_required(role='admin')
def admin_complaint_set_status(cid):
    status = request.form.get('status','OPEN')
    try:
        update_complaint_status(cid, status)
        flash('Complaint status updated.','success')
    except Exception as e:
        flash(f'Failed to update: {e}','danger')
    return redirect(url_for('admin_complaints'))

@app.route('/admin/users')
@login_required(role='admin')
def admin_users():
    users = query("SELECT id,name,email,phone,role,is_active,created_at FROM users ORDER BY created_at DESC")
    return render_template('admin_users.html', user=current_user(), users=users)

@app.route('/admin/users/<int:uid>/disable', methods=['POST'])
@login_required(role='admin')
def admin_user_disable(uid):
    execute("UPDATE users SET is_active=0 WHERE id=?", (uid,))
    flash('User disabled.','info')
    return redirect(request.referrer or url_for('admin_users'))

@app.route('/admin/users/<int:uid>/delete', methods=['POST'])
@login_required(role='admin')
def admin_user_delete(uid):
    urows = query("SELECT id, role FROM users WHERE id=?", (uid,))
    if not urows:
        flash('User not found.','warning'); return redirect(request.referrer or url_for('admin_users'))
    role = urows[0]['role']

    if role == 'store':
        srow = query("SELECT id FROM stores WHERE user_id=?", (uid,))
        sid = srow[0]['id'] if srow else None
        order_cnt = query("SELECT COUNT(*) c FROM orders WHERE store_id=?", (sid,))[0]['c'] if sid else 0
        if order_cnt and order_cnt > 0:
            execute("UPDATE users SET is_active=0 WHERE id=?", (uid,))
            flash("Store has orders; user disabled instead of hard delete.","warning")
            return redirect(request.referrer or url_for('admin_users'))
        if sid:
            execute("DELETE FROM products WHERE store_id=?", (sid,))
            execute("DELETE FROM stores WHERE id=?", (sid,))
        execute("DELETE FROM users WHERE id=?", (uid,))
        flash("Store user removed (no orders).","success")
        return redirect(request.referrer or url_for('admin_users'))

    if role == 'customer':
        oc = query("SELECT COUNT(*) c FROM orders WHERE user_id=?", (uid,))[0]['c']
        if oc and oc > 0:
            execute("UPDATE users SET is_active=0 WHERE id=?", (uid,))
            flash("Customer has orders; user disabled instead of hard delete.","warning")
            return redirect(request.referrer or url_for('admin_users'))
        execute("DELETE FROM addresses WHERE user_id=?", (uid,))
        execute("DELETE FROM users WHERE id=?", (uid,))
        flash("Customer removed.","success")
        return redirect(request.referrer or url_for('admin_users'))

    if role == 'delivery':
        oc = query("SELECT COUNT(*) c FROM orders WHERE delivery_partner_id=?", (uid,))[0]['c']
        if oc and oc > 0:
            execute("UPDATE users SET is_active=0 WHERE id=?", (uid,))
            flash("Delivery partner has order history; user disabled.","warning")
            return redirect(request.referrer or url_for('admin_users'))
        execute("DELETE FROM users WHERE id=?", (uid,))
        flash("Delivery partner removed.","success")
        return redirect(request.referrer or url_for('admin_users'))

    flash("Refused to delete admin via UI.","danger")
    return redirect(request.referrer or url_for('admin_users'))

# ----------------------
# STORE
# ----------------------
@app.route('/store')
@login_required(role='store')
def store_dashboard():
    u = current_user()
    store = query('SELECT * FROM stores WHERE user_id=?', (u['id'],))
    sid = store[0]['id'] if store else None

    products = query(
        'SELECT * FROM products WHERE store_id=? ORDER BY created_at DESC',
        (sid,)
    ) if sid else []

    orders = query('''
    SELECT o.*, 
           u.name  AS customer_name,
           u.phone AS customer_phone,
           oa.line1 AS addr_line1, oa.line2 AS addr_line2, oa.city AS addr_city,
           oa.state AS addr_state, oa.pincode AS addr_pincode, oa.latitude AS addr_lat, oa.longitude AS addr_lng
    FROM orders o
    JOIN users u ON u.id = o.user_id
    LEFT JOIN order_addresses oa ON oa.order_id = o.id
    WHERE o.store_id=? 
    GROUP BY o.id
    ORDER BY o.created_at DESC
''', (sid,)) if sid else []

    return render_template(
        'store_dashboard.html',
        user=u,
        store=store[0] if store else None,
        products=products,
        orders=orders
    )

@app.route('/store/product/new', methods=['POST'])
@login_required(role='store')
def store_product_new():
    u = current_user()
    sid = query('SELECT id FROM stores WHERE user_id=?', (u['id'],))[0]['id']
    name = request.form.get('name','').strip()
    price_per_kg = float(request.form.get('price_per_kg','0') or 0)
    stock_kg = float(request.form.get('stock_kg','0') or 0)
    image = request.files.get('image')

    image_path = None
    if image and '.' in image.filename and allowed_file(image.filename):
        fn = secure_filename(image.filename)
        save_as = datetime.utcnow().strftime('%Y%m%d%H%M%S_') + fn
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], save_as))
        image_path = f'uploads/{save_as}'

    execute('''INSERT INTO products (store_id,name,price_per_kg,stock_kg,image_path,is_active,created_at)
               VALUES (?,?,?,?,?,1,?)''',
            (sid, name, price_per_kg, stock_kg, image_path, datetime.utcnow().isoformat()))
    flash('Product added.','success')
    return redirect(url_for('store_dashboard'))

@app.route('/store/product/<int:pid>/toggle', methods=['POST'])
@login_required(role='store')
def store_product_toggle(pid):
    u = current_user()
    sid = query('SELECT id FROM stores WHERE user_id=?', (u['id'],))[0]['id']
    execute('UPDATE products SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE id=? AND store_id=?',
            (pid, sid))
    return redirect(url_for('store_dashboard'))

@app.route('/store/order/<int:oid>/status', methods=['POST'])
@login_required(role='store')
def store_order_status(oid):
    new_status = request.form.get('status','PLACED').upper()
    execute('UPDATE orders SET status=? WHERE id=?', (new_status, oid))
    add_order_event(oid, new_status)

    if new_status == 'DELIVERED':
        execute("UPDATE transactions SET status='PAID' WHERE order_id=?", (oid,))
        execute("UPDATE orders SET payment_status='PAID' WHERE id=?", (oid,))

    flash('Order status updated.','success')
    return redirect(url_for('store_dashboard'))

# --- API alias for order status so templates can call `api_order_status` ---
# --- Read-only JSON: current order status for live tracking ---
# --- Read-only JSON: current order status for live tracking ---
@app.route("/api/orders/<int:oid>/status", methods=["GET"], endpoint="api_order_status")
@login_required()
def api_order_status(oid):
    u = current_user()
    data = get_order_full(oid, for_user_id=u["id"] if u["role"] == "customer" else None)
    if not data:
        return jsonify({"ok": False, "error": "not found"}), 404

    o = data["order"]
    return jsonify({
        "ok": True,
        "id": o["id"],
        "status": o["status"],
        "payment_status": o["payment_status"],
        "delivery_partner_name": o.get("delivery_partner_name"),
        "events": data["events"],   # [{status,note,created_at}...]
    })



# ----------------------
# NEWSLETTER & UPLOADS
# ----------------------
@app.route('/newsletter/subscribe', methods=['POST'])
def newsletter_subscribe():
    email = request.form.get('email','').strip().lower()
    if not email or '@' not in email:
        flash('Please enter a valid email.','danger'); return redirect(request.referrer or url_for('index'))
    try:
        execute('INSERT INTO newsletter_subscribers (email, created_at) VALUES (?,?)', (email, datetime.utcnow().isoformat()))
        flash('Subscribed to newsletter!','success')
    except Exception:
        flash('You are already subscribed.','info')
    return redirect(request.referrer or url_for('index'))

@app.route('/uploads/<path:fn>')
def uploaded_file(fn):
    if '..' in fn or fn.startswith('/'):
        return abort(404)
    full = os.path.join(app.config['UPLOAD_FOLDER'], fn)
    if not os.path.isfile(full):
        return abort(404)
    return send_file(full)

@app.after_request
def add_no_cache_headers(resp):
    # help fetch() always get fresh data
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
