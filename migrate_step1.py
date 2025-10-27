# migrate_step1.py
from db import execute

# a) add store lat/lng (safe if columns already exist)
try: execute("ALTER TABLE stores ADD COLUMN latitude REAL")
except: pass
try: execute("ALTER TABLE stores ADD COLUMN longitude REAL")
except: pass

# b) add order-level delivery fields
try: execute("ALTER TABLE orders ADD COLUMN distance_km REAL DEFAULT 0")
except: pass
try: execute("ALTER TABLE orders ADD COLUMN delivery_fee REAL DEFAULT 0")
except: pass
try: execute("ALTER TABLE orders ADD COLUMN tip_amount REAL DEFAULT 0")
except: pass

# c) table to hold rider live location
execute("""
CREATE TABLE IF NOT EXISTS order_locations (
  order_id INTEGER PRIMARY KEY,
  rider_lat REAL,
  rider_lng REAL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id)
)
""")

print("Migration Step 1 done.")
