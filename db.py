import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import secrets
from typing import Optional, Tuple, List, Dict, Any
import io
import csv
import time  # <-- for retry backoff

DB_PATH = Path(__file__).with_name("app.db")


# -----------------------------------------
# Connection helpers: WAL + busy timeout + retries
# -----------------------------------------
def _connect() -> sqlite3.Connection:
    """
    Open a SQLite connection configured for better concurrency:
    - WAL journal (readers don't block writer)
    - busy_timeout (engine-level wait on locks)
    - check_same_thread=False (Flask may use threads)
    """
    conn = sqlite3.connect(
        DB_PATH,
        timeout=30,                # wait up to 30s on locks
        detect_types=sqlite3.PARSE_DECLTYPES,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    # Enable WAL & timeouts & FK enforcement each connection
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout = 30000;")  # 30 seconds
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


# kept for backward-compat with your code elsewhere
def get_conn() -> sqlite3.Connection:
    return _connect()


def _retry_sql(op, sql: str, params=(), attempts: int = 5):
    """
    Retry wrapper for transient 'database is locked' errors.
    Exponential backoff: 0.15s, 0.3s, 0.6s, 1.2s, 2.4s
    """
    delay = 0.15
    for i in range(attempts):
        try:
            return op(sql, params)
        except sqlite3.OperationalError as e:
            msg = str(e).lower()
            if ("database is locked" in msg) or ("database table is locked" in msg):
                if i == attempts - 1:
                    raise
                time.sleep(delay)
                delay *= 2
            else:
                raise


def _has_column(cur, table: str, column: str) -> bool:
    cur.execute(f"PRAGMA table_info({table})")
    return any(r[1] == column for r in cur.fetchall())


def init_db():
    # Use _connect so PRAGMAs apply on the first run too
    conn = _connect()
    cur = conn.cursor()

    # ---------- users / auth ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin','store','customer','delivery')),
        phone_verified INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS otp_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        consumed INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")

    # ---------- addresses ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS addresses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        label TEXT,
        line1 TEXT NOT NULL,
        line2 TEXT,
        city TEXT,
        state TEXT,
        pincode TEXT,
        latitude REAL,
        longitude REAL,
        is_default INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS order_addresses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        line1 TEXT NOT NULL,
        line2 TEXT,
        city TEXT,
        state TEXT,
        pincode TEXT,
        latitude REAL,
        longitude REAL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id)
    )""")

    # ---------- stores / catalog ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS stores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        store_name TEXT NOT NULL,
        address TEXT,
        created_at TEXT NOT NULL,
        latitude REAL,
        longitude REAL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        store_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        price_per_kg REAL NOT NULL,
        stock_kg REAL NOT NULL DEFAULT 0,
        image_path TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        FOREIGN KEY(store_id) REFERENCES stores(id)
    )""")

    # Add products.description if missing (for richer product page)
    if not _has_column(cur, "products", "description"):
        try:
            cur.execute("ALTER TABLE products ADD COLUMN description TEXT")
        except Exception:
            pass

    # === NEW: Catalog performance index (optional but helpful) ===
    cur.execute("CREATE INDEX IF NOT EXISTS idx_products_active_stock ON products(is_active, stock_kg)")

    # === NEW: Auto-toggle product visibility based on stock (SQLite triggers) ===
    # Deactivate when stock updated to 0 or below
    cur.execute("""
    CREATE TRIGGER IF NOT EXISTS trg_products_deactivate_on_update
    AFTER UPDATE OF stock_kg ON products
    FOR EACH ROW
    WHEN NEW.stock_kg <= 0
    BEGIN
      UPDATE products SET is_active = 0 WHERE id = NEW.id;
    END;
    """)
    # Reactivate when stock updated above 0
    cur.execute("""
    CREATE TRIGGER IF NOT EXISTS trg_products_reactivate_on_update
    AFTER UPDATE OF stock_kg ON products
    FOR EACH ROW
    WHEN NEW.stock_kg > 0
    BEGIN
      UPDATE products SET is_active = 1 WHERE id = NEW.id;
    END;
    """)
    # Handle inserts (new products created with zero stock should be hidden)
    cur.execute("""
    CREATE TRIGGER IF NOT EXISTS trg_products_deactivate_on_insert
    AFTER INSERT ON products
    FOR EACH ROW
    WHEN NEW.stock_kg <= 0
    BEGIN
      UPDATE products SET is_active = 0 WHERE id = NEW.id;
    END;
    """)
    cur.execute("""
    CREATE TRIGGER IF NOT EXISTS trg_products_reactivate_on_insert
    AFTER INSERT ON products
    FOR EACH ROW
    WHEN NEW.stock_kg > 0
    BEGIN
      UPDATE products SET is_active = 1 WHERE id = NEW.id;
    END;
    """)

    # ---------- cart ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS carts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS cart_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cart_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        weight_kg REAL NOT NULL,
        FOREIGN KEY(cart_id) REFERENCES carts(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )""")

    # --- DEDUPE EXISTING CART ITEMS BEFORE ADDING UNIQUE INDEX ---
    # For any (cart_id, product_id) that appears multiple times, keep the newest row (max id),
    # sum all weights into that row, and delete the others.
    cur.execute("""
        SELECT cart_id, product_id, MAX(id) AS keep_id, SUM(weight_kg) AS total_w, COUNT(*) AS cnt
        FROM cart_items
        GROUP BY cart_id, product_id
        HAVING cnt > 1
    """)
    dup_groups = cur.fetchall()
    for g in dup_groups:
        cart_id = g["cart_id"]
        product_id = g["product_id"]
        keep_id = g["keep_id"]
        total_w = g["total_w"]
        # put summed weight in the row we're keeping
        cur.execute("UPDATE cart_items SET weight_kg=? WHERE id=?", (total_w, keep_id))
        # remove other rows in the same group
        cur.execute("""
            DELETE FROM cart_items
            WHERE cart_id=? AND product_id=? AND id<>?
        """, (cart_id, product_id, keep_id))

    # Prevent duplicate products per cart going forward
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_cart_items_unique ON cart_items(cart_id, product_id)")

    # ---------- orders ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        store_id INTEGER NOT NULL,
        total_amount REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'PLACED',
        payment_status TEXT NOT NULL DEFAULT 'PENDING',
        delivery_partner_id INTEGER,
        delivery_fee REAL NOT NULL DEFAULT 0,
        distance_km REAL,
        tip_amount REAL NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(store_id) REFERENCES stores(id),
        FOREIGN KEY(delivery_partner_id) REFERENCES users(id)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        weight_kg REAL NOT NULL,
        unit_price_per_kg REAL NOT NULL,
        line_total REAL NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS order_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        status TEXT NOT NULL,
        note TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id)
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS delivery_assignments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        delivery_partner_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'ASSIGNED',
        assigned_at TEXT NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id),
        FOREIGN KEY(delivery_partner_id) REFERENCES users(id)
    )""")

    # ---------- payments ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        payment_method TEXT NOT NULL DEFAULT 'COD',
        status TEXT NOT NULL DEFAULT 'PENDING',
        created_at TEXT NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id)
    )""")

    # ---------- newsletter ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS newsletter_subscribers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL
    )""")

    # ---------- live GPS ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS delivery_locations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        delivery_partner_id INTEGER NOT NULL,
        order_id INTEGER,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        heading REAL,
        speed REAL,
        recorded_at TEXT NOT NULL,
        FOREIGN KEY(delivery_partner_id) REFERENCES users(id),
        FOREIGN KEY(order_id) REFERENCES orders(id)
    )""")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_delivery_locations_order_rec ON delivery_locations(order_id, recorded_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_delivery_locations_partner_rec ON delivery_locations(delivery_partner_id, recorded_at)")

    # ---------- ratings ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS product_ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
        comment TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(user_id, product_id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    )""")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_product_ratings_product ON product_ratings(product_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_product_ratings_user ON product_ratings(user_id)")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS store_ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        store_id INTEGER NOT NULL,
        rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
        comment TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(user_id, store_id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(store_id) REFERENCES stores(id)
    )""")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_store_ratings_store ON store_ratings(store_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_store_ratings_user ON store_ratings(user_id)")

    # ---------- complaints (target schema) ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS complaints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        store_id INTEGER,
        delivery_partner_id INTEGER,
        product_id INTEGER,
        order_id INTEGER,
        title TEXT,
        description TEXT,
        image_path TEXT,
        status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','REVIEWING','RESOLVED','DISMISSED')),
        created_at TEXT NOT NULL,
        resolved_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(store_id) REFERENCES stores(id),
        FOREIGN KEY(delivery_partner_id) REFERENCES users(id),
        FOREIGN KEY(product_id) REFERENCES products(id),
        FOREIGN KEY(order_id) REFERENCES orders(id)
    )""")

    # Ensure product_id exists if table pre-dates it
    if not _has_column(cur, "complaints", "product_id"):
        cur.execute("ALTER TABLE complaints ADD COLUMN product_id INTEGER")

    # ---------- migrate legacy complaints if needed ----------
    try:
        cur.execute("PRAGMA table_info(complaints)")
        cols = [r[1] for r in cur.fetchall()]
        if "reporter_user_id" in cols:  # legacy layout
            cur.execute("""
            CREATE TABLE IF NOT EXISTS complaints_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                store_id INTEGER,
                delivery_partner_id INTEGER,
                product_id INTEGER,
                order_id INTEGER,
                title TEXT,
                description TEXT,
                image_path TEXT,
                status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','REVIEWING','RESOLVED','DISMISSED')),
                created_at TEXT NOT NULL,
                resolved_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(store_id) REFERENCES stores(id),
                FOREIGN KEY(delivery_partner_id) REFERENCES users(id),
                FOREIGN KEY(product_id) REFERENCES products(id),
                FOREIGN KEY(order_id) REFERENCES orders(id)
            )""")
            cur.execute("""
            INSERT INTO complaints_new
                (user_id, store_id, delivery_partner_id, product_id, order_id, title, description, image_path, status, created_at, resolved_at)
            SELECT
                reporter_user_id,
                CASE WHEN target_type='store' THEN target_id END AS store_id,
                CASE WHEN target_type='delivery' THEN target_id END AS delivery_partner_id,
                CASE WHEN target_type='product' THEN target_id END AS product_id,
                order_id,
                'Complaint about ' || COALESCE(target_type, 'unknown') AS title,
                message AS description,
                NULL AS image_path,
                CASE
                    WHEN status IN ('OPEN','REVIEWING','RESOLVED','DISMISSED') THEN status
                    WHEN status='IN_REVIEW' THEN 'REVIEWING'
                    ELSE 'OPEN'
                END AS status,
                created_at,
                resolved_at
            FROM complaints
            """)
            cur.execute("DROP TABLE complaints")
            cur.execute("ALTER TABLE complaints_new RENAME TO complaints")
    except Exception as e:
        print("[WARN] Complaints migration skipped:", e)

    conn.commit()

    # seed admin if missing
    row = cur.execute("SELECT id FROM users WHERE email=?", ("admin@chhimphei.local",)).fetchone()
    if not row:
        now = datetime.utcnow().isoformat()
        cur.execute("""
            INSERT INTO users (name,email,phone,password_hash,role,phone_verified,is_active,created_at)
            VALUES (?,?,?,?, 'admin', 1, 1, ?)
        """, ("Administrator", "admin@chhimphei.local", "+911234567890", "!!set_in_app!!", now))
        conn.commit()

    conn.close()


def query(sql, params=()):
    conn = _connect()
    try:
        cur = conn.cursor()
        _retry_sql(cur.execute, sql, params)
        rows = cur.fetchall()
        return rows
    finally:
        conn.close()


def execute(sql, params=()):
    conn = _connect()
    try:
        cur = conn.cursor()
        _retry_sql(cur.execute, sql, params)
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


# === NEW: Safe stock adjust helper (clamps to >= 0; triggers handle is_active) ===
def adjust_product_stock(product_id: int, delta_kg: float):
    """
    Safely adjust stock (negative to reduce, positive to add).
    Triggers will auto-toggle is_active based on resulting stock.
    """
    execute(
        """
        UPDATE products
        SET stock_kg = MAX(0, stock_kg + ?)
        WHERE id = ?
        """,
        (float(delta_kg), int(product_id)),
    )


def add_order_event(order_id: int, status: str, note: str = ""):
    return execute(
        "INSERT INTO order_events (order_id, status, note, created_at) VALUES (?,?,?,?)",
        (order_id, status, note, datetime.utcnow().isoformat())
    )


def create_password_reset_token(user_id: int, minutes_valid: int = 30) -> str:
    token = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(minutes=minutes_valid)).isoformat()
    execute("""
        INSERT INTO password_reset_tokens (user_id, token, expires_at, consumed, created_at)
        VALUES (?,?,?,?,?)
    """, (user_id, token, expires, 0, datetime.utcnow().isoformat()))
    return token


def get_valid_reset_token(token: str):
    rows = query("""
        SELECT prt.*, u.email
        FROM password_reset_tokens prt
        JOIN users u ON u.id = prt.user_id
        WHERE prt.token=? AND prt.consumed=0
        ORDER BY prt.id DESC LIMIT 1
    """, (token,))
    if not rows:
        return None
    row = rows[0]
    try:
        if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
            return None
    except Exception:
        return None
    return row


def consume_reset_token(token: str):
    execute("UPDATE password_reset_tokens SET consumed=1 WHERE token=?", (token,))


def save_delivery_location(delivery_partner_id: int, latitude: float, longitude: float,
                           order_id: Optional[int] = None, heading: Optional[float] = None,
                           speed: Optional[float] = None):
    return execute("""
        INSERT INTO delivery_locations
            (delivery_partner_id, order_id, latitude, longitude, heading, speed, recorded_at)
        VALUES (?,?,?,?,?,?,?)
    """, (
        delivery_partner_id,
        order_id,
        float(latitude),
        float(longitude),
        float(heading) if heading is not None else None,
        float(speed) if speed is not None else None,
        datetime.utcnow().isoformat()
    ))


def get_latest_location_for_order(order_id: int):
    rows = query("""
        SELECT id, delivery_partner_id, order_id, latitude, longitude, heading, speed, recorded_at
        FROM delivery_locations
        WHERE order_id=?
        ORDER BY id DESC
        LIMIT 1
    """, (order_id,))
    return rows[0] if rows else None


def add_product_rating(user_id: int, product_id: int, rating: int, comment: Optional[str] = None):
    rating = max(1, min(5, int(rating)))
    try:
        return execute("""
            INSERT INTO product_ratings (user_id, product_id, rating, comment, created_at)
            VALUES (?,?,?,?,?)
        """, (user_id, product_id, rating, comment, datetime.utcnow().isoformat()))
    except sqlite3.IntegrityError:
        execute("""
            UPDATE product_ratings SET rating=?, comment=?, created_at=?
            WHERE user_id=? AND product_id=?
        """, (rating, comment, datetime.utcnow().isoformat(), user_id, product_id))
        return 0


def add_store_rating(user_id: int, store_id: int, rating: int, comment: Optional[str] = None):
    rating = max(1, min(5, int(rating)))
    try:
        return execute("""
            INSERT INTO store_ratings (user_id, store_id, rating, comment, created_at)
            VALUES (?,?,?,?,?)
        """, (user_id, store_id, rating, comment, datetime.utcnow().isoformat()))
    except sqlite3.IntegrityError:
        execute("""
            UPDATE store_ratings SET rating=?, comment=?, created_at=?
            WHERE user_id=? AND store_id=?
        """, (rating, comment, datetime.utcnow().isoformat(), user_id, store_id))
        return 0


def get_avg_rating_for_product(product_id: int) -> Tuple[float, int]:
    rows = query("""
        SELECT AVG(rating) AS avg_rating, COUNT(*) AS cnt
        FROM product_ratings
        WHERE product_id=?
    """, (product_id,))
    if not rows:
        return (0.0, 0)
    r = rows[0]
    return (float(r["avg_rating"] or 0.0), int(r["cnt"] or 0))


def get_avg_rating_for_store(store_id: int) -> Tuple[float, int]:
    rows = query("""
        SELECT AVG(rating) AS avg_rating, COUNT(*) AS cnt
        FROM store_ratings
        WHERE store_id=?
    """, (store_id,))
    if not rows:
        return (0.0, 0)
    r = rows[0]
    return (float(r["avg_rating"] or 0.0), int(r["cnt"] or 0))


def get_product_rating_summary(product_id: int) -> Dict[str, Any]:
    avg, cnt = get_avg_rating_for_product(product_id)
    return {"avg": round(avg, 2), "count": cnt}


def get_store_rating_summary(store_id: int) -> Dict[str, Any]:
    avg, cnt = get_avg_rating_for_store(store_id)
    return {"avg": round(avg, 2), "count": cnt}


# ---------- complaints helpers ----------
def file_complaint(user_id: int, target_type: str, target_id: int,
                   message: str, order_id: Optional[int] = None,
                   image_path: Optional[str] = None, title: Optional[str] = None) -> int:
    t = (target_type or "").lower()
    if t not in ("store", "delivery", "product"):
        raise ValueError("Invalid target_type")

    store_id = delivery_partner_id = product_id = None
    if t == "store":
        store_id = target_id
    elif t == "delivery":
        delivery_partner_id = target_id
    elif t == "product":
        product_id = target_id

    return execute("""
        INSERT INTO complaints (user_id, store_id, delivery_partner_id, product_id, order_id, title, description, image_path, status, created_at)
        VALUES (?,?,?,?,?,?,?,?, 'OPEN', ?)
    """, (user_id, store_id, delivery_partner_id, product_id, order_id,
          title or f"Complaint about {t}", message, image_path, datetime.utcnow().isoformat()))


def update_complaint_status(complaint_id: int, status: str):
    s = (status or "").upper()
    if s not in ("OPEN", "REVIEWING", "RESOLVED", "DISMISSED"):
        raise ValueError("Invalid complaint status")
    if s in ("RESOLVED", "DISMISSED"):
        execute("UPDATE complaints SET status=?, resolved_at=? WHERE id=?",
                (s, datetime.utcnow().isoformat(), complaint_id))
    else:
        execute("UPDATE complaints SET status=? WHERE id=?", (s, complaint_id))


def list_recent_complaints(limit: int = 100) -> List[sqlite3.Row]:
    # derive a readable target type + name + keep image
    return query("""
        SELECT
            c.*,
            u.name AS reporter_name,
            CASE
                WHEN c.product_id IS NOT NULL THEN 'product'
                WHEN c.delivery_partner_id IS NOT NULL THEN 'delivery'
                WHEN c.store_id IS NOT NULL THEN 'store'
                ELSE 'other'
            END AS target_kind,
            p.name AS product_name,
            s.store_name,
            dp.name AS delivery_partner_name
        FROM complaints c
        LEFT JOIN users u  ON u.id  = c.user_id
        LEFT JOIN products p ON p.id = c.product_id
        LEFT JOIN stores   s ON s.id = c.store_id
        LEFT JOIN users    dp ON dp.id = c.delivery_partner_id
        ORDER BY c.created_at DESC
        LIMIT ?
    """, (limit,))


# =========================================================
# NEW: Admin helpers for export & safe hard delete
# =========================================================

def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    rows = query("SELECT * FROM users WHERE id=?", (user_id,))
    return rows[0] if rows else None


def get_store_by_user(user_id: int) -> Optional[sqlite3.Row]:
    rows = query("SELECT * FROM stores WHERE user_id=?", (user_id,))
    return rows[0] if rows else None


def list_addresses_by_user(user_id: int) -> List[sqlite3.Row]:
    return query("SELECT * FROM addresses WHERE user_id=? ORDER BY created_at DESC", (user_id,))


def list_orders_by_customer(user_id: int) -> List[sqlite3.Row]:
    return query("SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC", (user_id,))


def list_orders_by_store_id(store_id: int) -> List[sqlite3.Row]:
    return query("SELECT * FROM orders WHERE store_id=? ORDER BY created_at DESC", (store_id,))


def list_orders_by_delivery_partner(user_id: int) -> List[sqlite3.Row]:
    return query("SELECT * FROM orders WHERE delivery_partner_id=? ORDER BY created_at DESC", (user_id,))


def list_order_items(order_ids: List[int]) -> List[sqlite3.Row]:
    if not order_ids:
        return []
    qmarks = ",".join(["?"] * len(order_ids))
    return query(f"SELECT * FROM order_items WHERE order_id IN ({qmarks}) ORDER BY id ASC", tuple(order_ids))


def list_transactions(order_ids: List[int]) -> List[sqlite3.Row]:
    if not order_ids:
        return []
    qmarks = ",".join(["?"] * len(order_ids))
    return query(f"SELECT * FROM transactions WHERE order_id IN ({qmarks}) ORDER BY created_at DESC", tuple(order_ids))


def list_products_by_store(store_id: int) -> List[sqlite3.Row]:
    return query("SELECT * FROM products WHERE store_id=? ORDER BY created_at DESC", (store_id,))


def list_complaints_related_to_user(user_id: int) -> Dict[str, List[sqlite3.Row]]:
    # reporter, against as delivery, against as store owner
    out: Dict[str, List[sqlite3.Row]] = {
        "filed_by_user": query("SELECT * FROM complaints WHERE user_id=? ORDER BY created_at DESC", (user_id,)),
        "against_user_as_delivery": query("SELECT * FROM complaints WHERE delivery_partner_id=? ORDER BY created_at DESC", (user_id,)),
    }
    st = get_store_by_user(user_id)
    if st:
        out["against_user_store"] = query("SELECT * FROM complaints WHERE store_id=? ORDER BY created_at DESC", (st["id"],))
    else:
        out["against_user_store"] = []
    return out


def get_user_export_tables(user_id: int) -> Dict[str, List[Dict[str, Any]]]:
    """
    Return a dict of table_name -> list of rows (as dicts) capturing
    everything tied to this account, so the caller can serialize to CSV/ZIP.
    """
    user = get_user_by_id(user_id)
    if not user:
        return {}

    result: Dict[str, List[Dict[str, Any]]] = {}

    def rows_to_dicts(rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
        return [dict(r) for r in rows]

    # core
    result["user"] = [dict(user)]
    result["addresses"] = rows_to_dicts(list_addresses_by_user(user_id))

    # as customer
    orders_cust = list_orders_by_customer(user_id)
    result["orders_as_customer"] = rows_to_dicts(orders_cust)
    result["order_items_as_customer"] = rows_to_dicts(list_order_items([o["id"] for o in orders_cust]))
    result["transactions_as_customer"] = rows_to_dicts(list_transactions([o["id"] for o in orders_cust]))

    # as store owner (if any)
    st = get_store_by_user(user_id)
    if st:
        result["store"] = [dict(st)]
        orders_store = list_orders_by_store_id(st["id"])
        result["orders_as_store"] = rows_to_dicts(orders_store)
        result["order_items_as_store"] = rows_to_dicts(list_order_items([o["id"] for o in orders_store]))
        result["transactions_as_store"] = rows_to_dicts(list_transactions([o["id"] for o in orders_store]))
        result["products"] = rows_to_dicts(list_products_by_store(st["id"]))
    else:
        result["store"] = []
        result["orders_as_store"] = []
        result["order_items_as_store"] = []
        result["transactions_as_store"] = []
        result["products"] = []

    # as delivery partner (if any)
    orders_deliv = list_orders_by_delivery_partner(user_id)
    result["orders_as_delivery"] = rows_to_dicts(orders_deliv)
    result["transactions_as_delivery"] = rows_to_dicts(list_transactions([o["id"] for o in orders_deliv]))

    # complaints
    cm = list_complaints_related_to_user(user_id)
    result["complaints_filed_by_user"] = rows_to_dicts(cm["filed_by_user"])
    result["complaints_against_user_as_delivery"] = rows_to_dicts(cm["against_user_as_delivery"])
    result["complaints_against_user_store"] = rows_to_dicts(cm["against_user_store"])

    return result


def render_export_to_csv_zip_bytes(user_id: int) -> bytes:
    """
    Build a ZIP (in-memory) with one CSV per section. Return bytes.
    The caller can send it via Flask send_file(io.BytesIO(...), ...)
    """
    import zipfile

    tables = get_user_export_tables(user_id)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        if not tables:
            # still include a README
            zf.writestr("README.txt", "User not found.")
            return buf.getvalue()

        for name, rows in tables.items():
            # write each list of dicts to CSV
            if not rows:
                # create an empty CSV with header note
                zf.writestr(f"{name}.csv", "")
                continue

            fieldnames = sorted({k for r in rows for k in r.keys()})
            out_io = io.StringIO()
            writer = csv.DictWriter(out_io, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for r in rows:
                writer.writerow({k: r.get(k, "") for k in fieldnames})
            zf.writestr(f"{name}.csv", out_io.getvalue())

        # Tiny manifest
        zf.writestr("manifest.txt", f"Export generated at {datetime.utcnow().isoformat()}Z for user_id={user_id}\n")

    return buf.getvalue()


def can_delete_user_hard(user_id: int) -> Tuple[bool, str]:
    """
    Check if user can be hard-deleted (no dependent data).
    Returns (ok, reason_if_false)
    """
    u = get_user_by_id(user_id)
    if not u:
        return False, "User not found."

    role = u["role"]
    if role == "admin":
        return False, "Refuse to delete admin via UI."

    if role == "store":
        st = get_store_by_user(user_id)
        if st:
            cnt = query("SELECT COUNT(*) c FROM orders WHERE store_id=?", (st["id"],))[0]["c"]
            if cnt and int(cnt) > 0:
                return False, "Store has orders; cannot hard-delete."
        # no orders – OK to delete
        return True, ""

    if role == "customer":
        cnt = query("SELECT COUNT(*) c FROM orders WHERE user_id=?", (user_id,))[0]["c"]
        if cnt and int(cnt) > 0:
            return False, "Customer has orders; cannot hard-delete."
        return True, ""

    if role == "delivery":
        cnt = query("SELECT COUNT(*) c FROM orders WHERE delivery_partner_id=?", (user_id,))[0]["c"]
        if cnt and int(cnt) > 0:
            return False, "Delivery partner has delivery history; cannot hard-delete."
        return True, ""

    return False, "Unsupported role."


def hard_delete_user(user_id: int) -> bool:
    """
    HARD delete a user that has no dependent data (validated by can_delete_user_hard).
    This removes related leaf records safely.
    Returns True if deleted, False otherwise.
    """
    ok, reason = can_delete_user_hard(user_id)
    if not ok:
        return False

    u = get_user_by_id(user_id)
    if not u:
        return False

    role = u["role"]

    # remove addresses
    execute("DELETE FROM addresses WHERE user_id=?", (user_id,))
    # remove carts & items
    cart_rows = query("SELECT id FROM carts WHERE user_id=?", (user_id,))
    if cart_rows:
        cart_ids = [r["id"] for r in cart_rows]
        if cart_ids:
            q = ",".join(["?"] * len(cart_ids))
            execute(f"DELETE FROM cart_items WHERE cart_id IN ({q})", tuple(cart_ids))
            execute(f"DELETE FROM carts WHERE id IN ({q})", tuple(cart_ids))

    # remove ratings authored by user
    execute("DELETE FROM product_ratings WHERE user_id=?", (user_id,))
    execute("DELETE FROM store_ratings   WHERE user_id=?", (user_id,))

    # remove complaints filed by user (we do NOT remove complaints against the store/partner, those belong to others)
    execute("DELETE FROM complaints WHERE user_id=?", (user_id,))

    if role == "store":
        st = get_store_by_user(user_id)
        if st:
            # no orders exist (pre-checked), safe to remove products & store
            execute("DELETE FROM products WHERE store_id=?", (st["id"],))
            execute("DELETE FROM stores WHERE id=?", (st["id"],))

    # finally remove the user
    execute("DELETE FROM users WHERE id=?", (user_id,))
    return True
