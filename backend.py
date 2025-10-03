from flask import Flask, request, Response, jsonify, session, send_from_directory, send_file, g, json
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from functools import wraps
import sqlite3
import os
from datetime import datetime, timedelta
from collections import Counter
import subprocess
import webbrowser
import threading
import time
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import traceback
import io
import csv
import pandas as pd
import re
from pathlib import Path


# ----------------- APP SETUP -----------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "smartbiz-secret")
CORS(app, supports_credentials=True)  # allow cookies/session headers

# Initialize SocketIO **after app is created**
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=True, async_mode="gevent"))

BASE_DIR = Path(__file__).resolve().parent

# ----------------- STATIC / UPLOADS -----------------
STATIC_DIR = BASE_DIR / "static"
PROFILE_IMG_FOLDER = STATIC_DIR / "profile_images"
PROFILE_IMG_FOLDER.mkdir(parents=True, exist_ok=True)

UPLOADS_DIR = BASE_DIR / "Owner" / "Ownerdata"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif", "mp4", "mov", "mp3", "wav", "pdf"}

# ----------------- DATABASE -----------------
DB_NAME = "smartbiz.db"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_NAME)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        # ----------- USERS -----------
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            phone TEXT,
            ice TEXT UNIQUE NOT NULL,
            role TEXT
        )''')

        # ----------- STORES -----------
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS stores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            ice TEXT UNIQUE NOT NULL,
            owner_id INTEGER,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )''')

        # ----------- WORKERS -----------
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS workers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT DEFAULT '',
            lastname TEXT DEFAULT '',
            email TEXT DEFAULT '',
            store_id INTEGER,
            profile_pic TEXT DEFAULT 'default.png',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (store_id) REFERENCES stores(id)
        )
        ''')

        # ----------- CHAT ------------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL,
                sender_type TEXT NOT NULL,
                sender_id TEXT NOT NULL,   -- changed to TEXT
                message TEXT NOT NULL,
                timestamp TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now'))
            )
        """)

        # ----------- SALES -----------
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            receipt_id TEXT DEFAULT NULL,
            store_id INTEGER,
            user_id INTEGER,
            product TEXT,
            quantity REAL,
            price REAL,
            total REAL,
            discount REAL,
            payment_method TEXT DEFAULT 'cash',
            timestamp TEXT DEFAULT (strftime('%Y-%m-%d %H:%M', 'now')),
            edited TEXT DEFAULT 'NO',
            edit_time TEXT DEFAULT NULL,
            editor TEXT DEFAULT NULL,
            log TEXT DEFAULT NULL,
            FOREIGN KEY (store_id) REFERENCES stores(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')

        # ----- INVENTORY CHECKER ------
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS inventory_checker (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                store_id INTEGER NOT NULL,
                worker_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                expected_quantity REAL,
                counted_quantity REAL,
                status TEXT,
                timestamp TEXT,
                FOREIGN KEY (store_id) REFERENCES stores(id),
                FOREIGN KEY (worker_id) REFERENCES workers(id),
                FOREIGN KEY (product_id) REFERENCES inventory(id)
            )
        """)

        # ---- Upgrade columns in SALES if missing ----
        required_sales_columns = {
            "payment_method": "TEXT DEFAULT 'cash'",
            "edited": "TEXT DEFAULT 'NO'",
            "edit_time": "TEXT DEFAULT NULL"
        }


        cursor.execute("PRAGMA table_info(sales)")
        existing_sales_columns = [col[1] for col in cursor.fetchall()]

        for col_name, col_type in required_sales_columns.items():
            if col_name not in existing_sales_columns:
                cursor.execute(f"ALTER TABLE sales ADD COLUMN {col_name} {col_type}")

        # ----------- INVENTORY -----------
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            store_id INTEGER,
            product TEXT,
            quantity INTEGER,
            cost REAL,
            price REAL,
            FOREIGN KEY (store_id) REFERENCES stores(id)
        )''')

        # ----------- PRICE HISTORY -----------
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS price_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            store_id INTEGER,
            product TEXT,
            old_price REAL,
            new_price REAL,
            change_percent REAL,
            changed_on TEXT DEFAULT (strftime('%Y-%m-%d %H:%M', 'now')),
            FOREIGN KEY (store_id) REFERENCES stores(id)
        )''')
        # ----------- CREDITS -----------
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS credits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            store_id INTEGER,
            tab_date TEXT DEFAULT (strftime('%Y-%m-%d %H:%M', 'now')),
            client TEXT,
            tab_value REAL,
            total REAL,
            user_id INTEGER,
            status TEXT DEFAULT 'Unpaid',
            payment_date TEXT,
            FOREIGN KEY (store_id) REFERENCES stores(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')

        conn.commit()

if not os.path.exists(DB_NAME):
    init_db()

    def create_default_admin():
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", ("admin",))
            if not cursor.fetchone():
                # Insert admin user (owner role)
                cursor.execute("""
                    INSERT INTO users (username, password, role)
                    VALUES (?, ?, ?)""", ("admin", "admin", "owner"))
                owner_id = cursor.lastrowid

                # Insert default store for admin
                cursor.execute("""
                    INSERT INTO stores (name, ice, owner_id)
                    VALUES (?, ?, ?)""", ("Default Store", "123456789", owner_id))
                store_id = cursor.lastrowid

                # Insert default worker linked to the store
                cursor.execute("""
                    INSERT INTO workers (username, password, store_id)
                    VALUES (?, ?, ?)""", ("worker", "worker", store_id))

                conn.commit()
                print("Default admin, store, and worker created.")
            else:
                print("Admin user already exists.")

    create_default_admin()

# === API Routes ===

@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    frontend_dir = r"D:\CODE PROJECTS\SME - Financial oversight and POS\Smart Biz Manager"
    return send_from_directory(frontend_dir, path)

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "ok"})


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")
    phone = data.get("phone")
    ice = data.get("ice")
    store_name = data.get("store")

    if not all([username, password, email, phone, store_name, ice]):
        return jsonify({"error": "All fields including ICE are required"}), 400

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username=?", (username,))
        if cursor.fetchone():
            return jsonify({"error": "Username already exists"}), 400

        # Create the user (owner)
        cursor.execute("""
            INSERT INTO users (username, password, email, phone, ice, role)
            VALUES (?, ?, ?, ?, ?, 'owner')
        """, (username, password, email, phone, ice))
        owner_id = cursor.lastrowid

        # Create the store
        cursor.execute("""
            INSERT INTO stores (name, ice, owner_id)
            VALUES (?, ?, ?)
        """, (store_name, ice, owner_id))

        conn.commit()

    return jsonify({"message": "Account and store created successfully."})


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # ---- Check owners ----
        cursor.execute("SELECT id, username, role, password FROM users WHERE username=?", (username,))
        row = cursor.fetchone()

        if row:
            # Uncomment if password hashing is used:
            # from werkzeug.security import check_password_hash
            # if not check_password_hash(row["password"], password):
            #     return jsonify({"error": "Invalid credentials"}), 401

            user_id = row["id"]
            role = row["role"] or "owner"

            cursor.execute("SELECT id, name FROM stores WHERE owner_id=?", (user_id,))
            stores = cursor.fetchall()
            stores_list = [{"id": s["id"], "name": s["name"]} for s in stores]

            session.permanent = True
            session['user_id'] = user_id
            session['role'] = role
            session['store_id'] = stores_list[0]['id'] if stores_list else None
            session['last_active'] = datetime.utcnow().isoformat()

            return jsonify({
                "user_id": user_id,
                "username": row["username"],
                "role": role,
                "stores": stores_list,
                "owner_id": user_id,
                "store_id": session['store_id']
            })

        # ---- Check workers ----
        cursor.execute("SELECT id, username, password, store_id FROM workers WHERE username=?", (username,))
        row = cursor.fetchone()

        if row:
            # Uncomment if password hashing is used
            # if not check_password_hash(row["password"], password):
            #     return jsonify({"error": "Invalid credentials"}), 401

            user_id = row["id"]
            store_id = row["store_id"]

            cursor.execute("SELECT name FROM stores WHERE id=?", (store_id,))
            store_row = cursor.fetchone()
            store_name = store_row["name"] if store_row else "Unknown Store"

            session.permanent = True
            session['user_id'] = user_id
            session['role'] = "worker"
            session['store_id'] = store_id
            session['last_active'] = datetime.utcnow().isoformat()

            return jsonify({
                "user_id": user_id,
                "username": row["username"],
                "role": "worker",
                "stores": [{"id": store_id, "name": store_name}],
                "store_id": store_id
            })

    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/session_user")
def session_user():
    return jsonify({
        "user_id": session.get("user_id"),
        "role": session.get("role"),
        "store_id": session.get("store_id")
    })

@app.route("/logout")
def logout():
    session.clear()
    return jsonify({"msg": "Logged out"})

@app.route("/verify_password", methods=["POST"])
def verify_password():
    data = request.get_json()
    user_id = data.get("user_id")
    input_password = data.get("password")

    if not user_id or not input_password:
        return jsonify({"error": "Missing credentials"}), 400

    #conn = sqlite3.connect("smartbiz.db")
    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "User not found"}), 404

        stored_hash = row[0]
        if check_password_hash(stored_hash, input_password):
            return jsonify({"valid": True}), 200
        else:
            return jsonify({"valid": False}), 401
    except Exception as e:
        print("❌ Password verification error:", e)
        return jsonify({"error": "Verification failed"}), 500
    finally:
        conn.close()

@app.route("/add_store", methods=["POST"])
def add_store():
    data = request.get_json()
    name = data.get("name")
    ice = data.get("ice")
    owner_id = data.get("owner_id")

    if not name or not ice or not owner_id:
        return jsonify({"error": "Missing store data"}), 400

    con = sqlite3.connect(DB_NAME)
    cur = con.cursor()
    cur.execute("INSERT INTO stores (name, ice, owner_id) VALUES (?, ?, ?)", (name, ice, owner_id))
    con.commit()
    con.close()
    return jsonify({"message": "Store added successfully."})

@app.route("/remove_store", methods=["POST"])
def remove_store():
    data = request.get_json()
    store_id = data.get("id")

    if not store_id:
        return jsonify({"error": "Missing store ID"}), 400

    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM stores WHERE id = ?", (store_id,))
        conn.commit()
        return jsonify({"success": True}), 200
    except Exception as e:
        print("❌ Error deleting store:", e)
        return jsonify({"error": "Failed to delete store"}), 500
    finally:
        conn.close()

@app.route("/get_stores", methods=["POST"])
def get_stores():
    data = request.get_json()
    owner_id = data.get("owner_id") if data else None

    if not owner_id:
        return jsonify({"error": "Missing owner_id"}), 400

    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()
    try:
        # Only fetch stores that belong to this owner
        cursor.execute("SELECT id, name, ice FROM stores WHERE owner_id = ?", (owner_id,))
        stores = [{"id": row[0], "name": row[1], "ice": row[2]} for row in cursor.fetchall()]
        return jsonify(stores)
    except Exception as e:
        print("Error in /get_stores:", e)
        return jsonify({"error": "Failed to fetch stores"}), 500
    finally:
        conn.close()

@app.route("/update_store", methods=["POST"])
def update_store():
    data = request.get_json()
    store_id = data.get("id")
    name = data.get("name")
    ice = data.get("ice")

    if not all([store_id, name, ice]):
        return jsonify({"error": "Missing required fields"}), 400

    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE stores SET name = ?, ice = ? WHERE id = ?
        """, (name, ice, store_id))
        conn.commit()
        return jsonify({"success": True}), 200
    except Exception as e:
        print("❌ Store update error:", e)
        return jsonify({"error": "Failed to update store"}), 500
    finally:
        conn.close()

@app.route("/get_performance_data")
def get_performance_data():
    try:
        store_id = request.args.get("store_id")
        user_id = request.args.get("user_id")

        if user_id is None:
            return jsonify({"error": "Missing user_id"}), 400

        try:
            user_id = int(user_id)
        except ValueError:
            return jsonify({"error": "Invalid user_id"}), 400

        if store_id and store_id != "all":
            try:
                store_id = int(store_id)
            except ValueError:
                return jsonify({"error": "Invalid store_id"}), 400

        conn = sqlite3.connect("smartbiz.db")
        cursor = conn.cursor()
        is_all = (store_id == "all" or store_id is None)

        # We'll filter sales by store owned by this user.
        # First, prepare a base join SQL snippet for filtering by owner:
        # sales JOIN stores ON sales.store_id = stores.id AND stores.owner_id = ?

        owner_filter = "stores.owner_id = ?"
        params = [user_id]

        # If specific store is selected, add it to filter params
        if not is_all:
            owner_filter += " AND sales.store_id = ?"
            params.append(store_id)

        # === Total Revenue ===
        query = f"""
            SELECT IFNULL(SUM(sales.total), 0)
            FROM sales
            JOIN stores ON sales.store_id = stores.id
            WHERE {owner_filter}
        """
        cursor.execute(query, params)
        total_revenue = cursor.fetchone()[0]

        # === Total Items Sold ===
        query = f"""
            SELECT IFNULL(SUM(sales.quantity), 0)
            FROM sales
            JOIN stores ON sales.store_id = stores.id
            WHERE {owner_filter}
        """
        cursor.execute(query, params)
        total_items_sold = cursor.fetchone()[0]

        # === Total Transactions ===
        query = f"""
            SELECT COUNT(*)
            FROM sales
            JOIN stores ON sales.store_id = stores.id
            WHERE {owner_filter}
        """
        cursor.execute(query, params)
        total_transactions = cursor.fetchone()[0]

        # === Profit ===
        query_profit = f"""
            SELECT IFNULL(SUM((sales.price - inventory.cost) * sales.quantity), 0)
            FROM sales
            JOIN stores ON sales.store_id = stores.id
            LEFT JOIN inventory ON sales.store_id = inventory.store_id AND sales.product = inventory.product
            WHERE {owner_filter}
        """
        cursor.execute(query_profit, params)
        total_profit = cursor.fetchone()[0]

        # === KPI calculations ===
        avg_basket_size = round(total_items_sold / total_transactions, 2) if total_transactions else 0
        avg_sale_value = round(total_revenue / total_transactions, 2) if total_transactions else 0
        profit_margin = round((total_profit / total_revenue) * 100, 2) if total_revenue else 0

        # === Payment Breakdown ===
        query = f"""
            SELECT sales.payment_method, IFNULL(SUM(sales.total), 0)
            FROM sales
            JOIN stores ON sales.store_id = stores.id
            WHERE {owner_filter}
            GROUP BY sales.payment_method
        """
        cursor.execute(query, params)
        rows = cursor.fetchall()
        payments = {"cash": 0, "credit": 0}
        for method, amount in rows:
            if method and method.lower() == "credit":
                payments["credit"] += amount
            else:
                payments["cash"] += amount

        # === Sales Trend (last 7 days) ===
        query = f"""
            SELECT strftime('%w', sales.timestamp) as weekday, IFNULL(SUM(sales.total), 0)
            FROM sales
            JOIN stores ON sales.store_id = stores.id
            WHERE {owner_filter}
            AND date(sales.timestamp) >= date('now', '-6 days')
            GROUP BY weekday
            ORDER BY weekday ASC
        """
        cursor.execute(query, params)
        trend_data = cursor.fetchall()
        weekday_map = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
        trend_dict = {int(day): total for day, total in trend_data}
        sales_trend = {
            "labels": [weekday_map[i] for i in range(7)],
            "data": [trend_dict.get(i, 0) for i in range(7)]
        }

        # === Sales By Hour ===
        query = f"""
            SELECT strftime('%H', sales.timestamp) as hour, IFNULL(SUM(sales.total), 0)
            FROM sales
            JOIN stores ON sales.store_id = stores.id
            WHERE {owner_filter}
            GROUP BY hour
            ORDER BY hour ASC
        """
        cursor.execute(query, params)
        hour_data = cursor.fetchall()
        sales_by_hour = {
            "labels": [],
            "data": []
        }
        for hour, total in hour_data:
            label = f"{int(hour)}h"
            sales_by_hour["labels"].append(label)
            sales_by_hour["data"].append(total)

        conn.close()

        return jsonify({
            "kpis": {
                "total_revenue": total_revenue,
                "total_items_sold": total_items_sold,
                "total_transactions": total_transactions,
                "avg_basket_size": avg_basket_size,
                "avg_sale_value": avg_sale_value,
                "profit_margin": profit_margin
            },
            "charts": {
                "sales_trend": sales_trend,
                "sales_by_hour": sales_by_hour,
                "payments": payments
            }
        })

    except Exception as e:
        print("❌ Error in /get_performance_data:", e)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/add_user', methods=['POST'])
def add_user():
    print("📩 /add_user called")
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    store_id = data.get('store_id')

    if not all([username, password, role]):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400

    conn = sqlite3.connect('smartbiz.db')
    cursor = conn.cursor()

    try:
        if role == "worker":
            if not store_id:
                return jsonify({'success': False, 'error': 'Store ID required for worker'}), 400
            cursor.execute("""
                INSERT INTO workers (username, password, store_id, created_at, profile_pic)
                VALUES (?, ?, ?, datetime('now'), '/static/profile_images/default_profile.png')
            """, (username, password, store_id))
        elif role == "owner":
            cursor.execute("""
                INSERT INTO users (username, password, role, created_at, profile_pic)
                VALUES (?, ?, ?, datetime('now'), '/static/profile_images/default_profile.png')
            """, (username, password, role))
        else:
            return jsonify({'success': False, 'error': 'Invalid role'}), 400

        conn.commit()
        return jsonify({'success': True})

    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'Username already exists'}), 409
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()

@app.route("/delete_user", methods=["POST"])
def delete_user():
    data = request.get_json()
    user_id = data.get("user_id")
    role = data.get("role")  # 🆕 Expecting role from frontend

    if not user_id or not role:
        return jsonify({"error": "Missing user_id or role"}), 400

    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()

    try:
        if role == "worker":
            cursor.execute("DELETE FROM workers WHERE id = ?", (user_id,))
        else:
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return jsonify({"message": "User deleted successfully."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/get_users", methods=["POST"])
def get_users():
    try:
        data = request.get_json()
        owner_id = data.get("owner_id")

        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            # 1. Get owners (only this owner)
            cursor.execute("""
                SELECT u.id, u.username, u.role, s.name as store_name
                FROM users u
                LEFT JOIN stores s ON s.owner_id = u.id
                WHERE u.id = ?
            """, (owner_id,))
            owners = cursor.fetchall()

            # 2. Get workers belonging to this owner's stores
            cursor.execute("""
                SELECT w.id, w.username, 'worker' as role, s.name as store_name
                FROM workers w
                LEFT JOIN stores s ON w.store_id = s.id
                WHERE s.owner_id = ?
            """, (owner_id,))
            workers = cursor.fetchall()

        # Format nicely for JS
        def format_user(row):
            return {
                "id": row[0],
                "username": row[1],
                "role": row[2],
                "store_name": row[3] if row[3] else "N/A"
            }

        all_users = [format_user(r) for r in owners + workers]
        return jsonify(all_users)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/get_workers")  # Not used yet as of 16/07/25
def get_workers():
    con = sqlite3.connect(DB_NAME)
    cur = con.cursor()
    cur.execute("""
        SELECT workers.id, workers.username, workers.store_id, stores.name AS store_name
        FROM workers
        JOIN stores ON workers.store_id = stores.id
    """)
    rows = cur.fetchall()
    con.close()
    return jsonify([
        {
            "id": row[0],
            "username": row[1],
            "store_id": row[2],
            "store_name": row[3]
        }
        for row in rows
    ])

#@app.route("/get_users", methods=["POST"])
#def get_users():
#    data = request.get_json()
#    owner_id = data.get("owner_id")
#
#    conn = sqlite3.connect("smartbiz.db")
#    cursor = conn.cursor()
#
#    query = """
#        SELECT users.id, users.username, users.role, users.store_id, stores.name
#        FROM users
#        LEFT JOIN stores ON users.store_id = stores.id
#        WHERE stores.owner_id = ?
#    """
#    users = cursor.execute(query, (owner_id,)).fetchall()
#
#    result = [
#        {
#            "user_id": u[0],
#            "username": u[1],
#            "role": u[2],
#            "store_id": u[3],
#            "store_name": u[4],
#        }
#        for u in users
#    ]
#
#    conn.close()
#    return jsonify(result)
#
#@app.route("/get_users")
#def get_users():
#    con = sqlite3.connect(DB_NAME)
#    cur = con.cursor()
#    # Include store_id in select
#    cur.execute("SELECT id, username, role, store_id FROM users")
#    rows = cur.fetchall()
#    con.close()
#    # Return store_id as well
#    return jsonify([
#        {
#            "id": r[0],
#            "username": r[1],
#            "role": r[2],
#            "store_id": r[3]  # Add store_id here
#        }
#        for r in rows
#    ])
#

@app.route("/edit_sale", methods=["POST"])
def edit_sale():
    data = request.get_json()
    sale_id = data.get("sale_id")
    new_qty = data.get("quantity")
    discount = data.get("discount", 0)

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Get old sale details
    cur.execute("SELECT * FROM sales WHERE id = ?", (sale_id,))
    sale = cur.fetchone()
    if not sale:
        return jsonify({"success": False, "error": "Sale not found"})

    product = sale["product"]
    old_qty = sale["quantity"]
    price = sale["price"]
    store_id = sale["store_id"]

    qty_diff = new_qty - old_qty

    # Adjust inventory
    cur.execute("""
        UPDATE inventory
        SET quantity = quantity - ?
        WHERE product = ? AND store_id = ?
    """, (qty_diff, product, store_id))

    # Update sale record
    total = (price * new_qty) - discount
    cur.execute("""
        UPDATE sales
        SET quantity = ?, discount = ?, total = ?
        WHERE id = ?
    """, (new_qty, discount, total, sale_id))

    conn.commit()
    conn.close()

    return jsonify({"success": True})

@app.route("/delete_sale", methods=["POST"])
def delete_sale():
    data = request.get_json()
    sale_id = data.get("sale_id")
    username = data.get("username")  # Sent from frontend (from getCurrentUser())
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "error": "Missing credentials"})

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Check password of worker with matching username
    cur.execute("SELECT id, password FROM workers WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "error": "Worker not found"})

    if row["password"] != password:
        conn.close()
        return jsonify({"success": False, "error": "Invalid password"})

    user_id = row["id"]

    # Fetch the sale
    cur.execute("SELECT * FROM sales WHERE id = ?", (sale_id,))
    sale = cur.fetchone()
    if not sale:
        conn.close()
        return jsonify({"success": False, "error": "Sale not found"})

    product = sale["product"]
    quantity = sale["quantity"]
    store_id = sale["store_id"]

    # Update inventory
    cur.execute("""
        UPDATE inventory 
        SET quantity = quantity + ?
        WHERE product = ? AND store_id = ?
    """, (quantity, product, store_id))

    # Delete sale
    cur.execute("DELETE FROM sales WHERE id = ?", (sale_id,))

    conn.commit()
    conn.close()

    return jsonify({"success": True})

@app.route("/get_sales_by_receipt", methods=["POST"])
def get_sales_by_receipt():
    data = request.get_json()
    receipt_id = data.get("receipt_id")
    store_id = data.get("store_id")

    if not receipt_id or not store_id:
        return jsonify([])

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Search all sales in the current store by receipt ID
    cur.execute("""
        SELECT * FROM sales 
        WHERE receipt_id = ? AND store_id = ? 
        ORDER BY timestamp ASC
    """, (receipt_id, store_id))

    sales = [dict(row) for row in cur.fetchall()]
    conn.close()

    return jsonify(sales)

@app.route("/get_sales", methods=["POST"])
def get_sales():
    data = request.json
    print("Received data:", data)
    store_id = data.get("store_id")
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT timestamp, product, quantity, price, total
            FROM sales
            WHERE store_id=?
            ORDER BY timestamp DESC
        """, (store_id,))
        rows = cursor.fetchall()
        return jsonify([
            {
                "timestamp": row[0],
                "product": row[1],
                "quantity": row[2],
                "price": row[3],
                "total": row[4]
            }
            for row in rows
        ])

@app.route("/submit_sale", methods=["POST"])
def submit_sale():
    data = request.get_json()
    print("🧾 Sale data received:", data)

    # Validate required fields
    if "store_id" not in data or "user_id" not in data or "items" not in data:
        return jsonify({"success": False, "error": "Missing store_id, user_id, or items"}), 400

    items = data["items"]
    payment_method = data.get("payment_method", "Cash")
    basket_discount = float(data.get("discount", 0))

    if not isinstance(items, list) or len(items) == 0:
        return jsonify({"success": False, "error": "Items must be a non-empty list"}), 400

    # Use single timestamp for all items in this transaction
    now = datetime.now().isoformat()
    receipt_id = re.sub(r"[^\w]", "", now)  # e.g., 2025-08-06T03:30:12.123456 -> 20250806T033012123456

    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()

            # Fetch store ICE from stores table using store_id
            cursor.execute("SELECT ice FROM stores WHERE id = ?", (data["store_id"],))
            store_ice_row = cursor.fetchone()
            store_ice = store_ice_row[0] if store_ice_row else "N/A"

            for idx, item in enumerate(items):
                print(f"🔍 Checking item {idx + 1}: {item}")
                required_fields = ["product", "quantity", "price", "total"]
                for field in required_fields:
                    if field not in item:
                        return jsonify({
                            "success": False,
                            "error": f"Missing field '{field}' in item {idx + 1}: {item}"
                        }), 400

                product = item["product"]
                quantity = item["quantity"]
                price = item["price"]
                total = item["total"]
                item_discount = float(item.get("discount", 0))

                # Insert sale with receipt_id
                cursor.execute("""
                    INSERT INTO sales (
                        store_id, user_id, product, quantity, price, total, discount,
                        timestamp, payment_method, receipt_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    data["store_id"],
                    data["user_id"],
                    product,
                    quantity,
                    price,
                    total,
                    item_discount,
                    now,
                    payment_method,
                    receipt_id
                ))

                # Update inventory
                cursor.execute(
                    "SELECT id, quantity FROM inventory WHERE store_id=? AND product=?",
                    (data["store_id"], product)
                )
                row = cursor.fetchone()
                if row:
                    new_qty = max(0, row[1] - quantity)
                    cursor.execute(
                        "UPDATE inventory SET quantity=? WHERE id=?",
                        (new_qty, row[0])
                    )

            conn.commit()
        return jsonify({
            "success": True,
            "message": "✅ Sale(s) recorded",
            "receipt_id": receipt_id,
            "store_ice": store_ice
        })

    except Exception as e:
        print("❌ Error during sale:", str(e))
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/update_inventory", methods=["POST"])
# Worker
def update_inventory():
    data = request.get_json()
    store_id = data.get("store_id")
    product = data.get("product")
    quantity = data.get("quantity")  # Can be negative

    if not all([store_id, product, quantity is not None]):
        return jsonify({"error": "Missing required fields"}), 400

    conn = sqlite3.connect("smartbiz.db")
    cur = conn.cursor()

    cur.execute("SELECT quantity FROM inventory WHERE store_id = ? AND product = ?", (store_id, product))
    result = cur.fetchone()
    if not result:
        conn.close()
        return jsonify({"error": "Product not found in inventory"}), 404

    current_qty = result[0]
    new_qty = max(0, current_qty + quantity)

    cur.execute("UPDATE inventory SET quantity = ? WHERE store_id = ? AND product = ?", (new_qty, store_id, product))
    conn.commit()
    conn.close()

    return jsonify({"message": "Inventory updated", "new_quantity": new_qty})

@app.route("/get_inventory", methods=["POST"])
def get_inventory():
    data = request.json
    store_id = data.get("store_id")
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT product, quantity, price FROM inventory WHERE store_id=?", (store_id,))
        rows = cursor.fetchall()
        inventory_list = [{"product": row[0], "quantity": row[1], "price": row[2]} for row in rows]
        return jsonify({"inventory": inventory_list})

@app.route("/add_inventory_check", methods=["POST"])
def add_inventory_check():
    data = request.get_json()
    store_id = data.get("store_id")
    worker_id = data.get("worker_id")
    product_id = data.get("product_id")
    counted_quantity = data.get("counted_quantity")

    if not all([store_id, worker_id, product_id, counted_quantity is not None]):
        return jsonify({"error": "Missing fields"}), 400

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        # Get expected quantity
        cursor.execute("SELECT quantity FROM inventory WHERE id=?", (product_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Product not found"}), 404

        expected_quantity = row[0]
        status = "validated" if expected_quantity == counted_quantity else "mismatch"

        cursor.execute("""
            INSERT INTO inventory_checker (store_id, worker_id, product_id, expected_quantity, counted_quantity, status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        """, (store_id, worker_id, product_id, expected_quantity, counted_quantity, status))
        conn.commit()

    return jsonify({"message": "✅ Inventory check recorded", "status": status})

@app.route("/get_inventory_checks", methods=["POST"])
def get_inventory_checks():
    data = request.get_json()
    store_id = data.get("store_id")

    if not store_id:
        return jsonify({"error": "Missing store_id"}), 400

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ic.id, w.username, i.product, ic.expected_quantity, ic.counted_quantity, ic.status, ic.timestamp, ic.product_id
            FROM inventory_checker ic
            LEFT JOIN workers w ON ic.worker_id = w.id
            LEFT JOIN inventory i ON ic.product_id = i.id
            WHERE ic.store_id = ?
            ORDER BY ic.timestamp DESC
        """, (store_id,))
        rows = cursor.fetchall()

    checks = [
        {
            "id": r[0],
            "worker": r[1],
            "product": r[2],
            "expected": r[3],
            "counted": r[4],
            "status": r[5],
            "timestamp": r[6],
            "product_id": r[7]
        } for r in rows
    ]

    return jsonify(checks)

@app.route("/validate_mismatch", methods=["POST"])
def validate_mismatch():
    data = request.get_json() or {}
    checker_id = data.get("checker_id")
    if not checker_id:
        return jsonify({"error": "Missing checker_id"}), 400

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # Get the inventory_checker record
        cursor.execute("SELECT store_id, product_id, counted_quantity FROM inventory_checker WHERE id = ?", (checker_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Inventory check record not found"}), 404

        store_id, product_id, counted_quantity = row

        # Update inventory: set quantity to counted_quantity for that inventory row
        cursor.execute("SELECT quantity FROM inventory WHERE id = ? AND store_id = ?", (product_id, store_id))
        inv_row = cursor.fetchone()
        if not inv_row:
            return jsonify({"error": "Inventory item not found for this store"}), 404

        cursor.execute("UPDATE inventory SET quantity = ? WHERE id = ? AND store_id = ?", (counted_quantity, product_id, store_id))

        # Update the inventory_checker status to approved
        cursor.execute("UPDATE inventory_checker SET status = ?, timestamp = datetime('now') WHERE id = ?", ("approved", checker_id))

        conn.commit()

    return jsonify({"message": "Inventory corrected to counted value and check marked approved."})

@app.route("/disprove_mismatch", methods=["POST"])
def disprove_mismatch():
    data = request.get_json() or {}
    checker_id = data.get("checker_id")
    if not checker_id:
        return jsonify({"error": "Missing checker_id"}), 400

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM inventory_checker WHERE id = ?", (checker_id,))
        if not cursor.fetchone():
            return jsonify({"error": "Inventory check record not found"}), 404

        cursor.execute("UPDATE inventory_checker SET status = ?, timestamp = datetime('now') WHERE id = ?", ("disproved", checker_id))
        conn.commit()

    return jsonify({"message": "Inventory check marked as disproved."})

@app.route("/status_log/<int:product_id>", methods=["GET"])
def get_status_log(product_id):
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT ic.id, ic.timestamp, ic.expected_quantity, ic.counted_quantity,
                       w.name, w.lastname
                FROM inventory_checker ic
                JOIN workers w ON ic.worker_id = w.id
                WHERE ic.product_id = ? AND ic.status = 'disproved'
                ORDER BY ic.timestamp DESC
            """, (product_id,))
            rows = c.fetchall()

        logs = [
            {
                "id": row[0],
                "timestamp": row[1],
                "expected": row[2],
                "counted": row[3],
                "worker": f"{row[4]} {row[5]}".strip()
            }
            for row in rows
        ]
        return jsonify({"status_log": logs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/get_disproved_checks", methods=["POST"])
def get_disproved_checks():
    data = request.get_json()
    store_id = data.get("store_id")
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT ic.timestamp, w.username as worker, i.product,
                   ic.expected_quantity, ic.counted_quantity
            FROM inventory_checker ic
            LEFT JOIN workers w ON w.id = ic.worker_id
            LEFT JOIN inventory i ON i.id = ic.product_id
            WHERE ic.store_id=? AND ic.status='mismatch'
            ORDER BY ic.timestamp DESC
        """, (store_id,))
        rows = c.fetchall()
    return jsonify({"status_log": [
        {
            "timestamp": r[0],
            "worker": r[1],
            "product": r[2],
            "expected": r[3],
            "counted": r[4]
        } for r in rows
    ]})

@app.route("/owner_validate_check", methods=["POST"])
def owner_validate_check():
    data = request.get_json()
    check_id = data.get("check_id")
    owner_id = data.get("owner_id")
    approve = data.get("approve")  # True or False

    if not all([check_id, owner_id, approve is not None]):
        return jsonify({"error": "Missing fields"}), 400

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        # 1. Get check entry
        cursor.execute("""
            SELECT ic.store_id, ic.product_id, ic.counted_quantity, ic.expected_quantity
            FROM inventory_checker ic
            JOIN stores s ON ic.store_id = s.id
            WHERE ic.id=? AND s.owner_id=?
        """, (check_id, owner_id))
        row = cursor.fetchone()

        if not row:
            return jsonify({"error": "Check not found or not authorized"}), 404

        store_id, product_id, counted_quantity, expected_quantity = row

        if approve:
            # 2. Update inventory with counted quantity
            cursor.execute("UPDATE inventory SET quantity=? WHERE id=?", (counted_quantity, product_id))

            # 3. Update status in check log
            cursor.execute("UPDATE inventory_checker SET status=? WHERE id=?", ("approved", check_id))
        else:
            # Reject without changing inventory
            cursor.execute("UPDATE inventory_checker SET status=? WHERE id=?", ("rejected", check_id))

        conn.commit()

    return jsonify({"message": "✅ Validation processed", "approved": approve})

@app.route("/get_kpis", methods=["POST"])
def get_kpis():
    data = request.json
    store_id = data["store_id"]

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()

        # Total revenue
        cursor.execute("SELECT SUM(total) FROM sales WHERE store_id=?", (store_id,))
        revenue = cursor.fetchone()[0] or 0

        # Total credits
        cursor.execute("SELECT SUM(total) FROM credits WHERE store_id=?", (store_id,))
        credits = cursor.fetchone()[0] or 0

        # Join sales with inventory to get cost of goods sold
        cursor.execute("""
            SELECT s.quantity, i.cost
            FROM sales s
            JOIN inventory i 
              ON s.product = i.product AND s.store_id = i.store_id
            WHERE s.store_id=?
        """, (store_id,))
        cost_items = cursor.fetchall()

        total_cost = sum(qty * cost for qty, cost in cost_items)

        profit = revenue - total_cost

    return jsonify({
        "revenue": revenue,
        "credits": credits,
        "cost": round(total_cost, 2),
        "profit": round(profit, 2)
    })

@app.route("/owner_product_list", methods=["POST"])
def owner_product_list():
    data = request.get_json()
    owner_id = data.get("owner_id")
    if not owner_id:
        return jsonify({"error": "owner_id missing"}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT DISTINCT inventory.product
        FROM inventory
        JOIN stores ON stores.id = inventory.store_id
        WHERE stores.owner_id = ?
    """, (owner_id,))

    products = [{"product": row[0]} for row in cursor.fetchall()]
    conn.close()
    return jsonify(products)

@app.route("/get_product_kpis", methods=["POST"])
def get_product_kpis():
    data = request.get_json()
    owner_id = data.get("owner_id")
    product = data.get("product")
    date_from = data.get("date_from")  # expected format 'YYYY-MM-DD' or None
    date_to = data.get("date_to")

    if not owner_id or not product:
        return jsonify({"error": "owner_id or product missing"}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Get all store ids owned by this owner
    cursor.execute("SELECT id, name FROM stores WHERE owner_id = ?", (owner_id,))
    stores = cursor.fetchall()
    store_map = {sid: sname for sid, sname in stores}
    store_ids = tuple(store_map.keys())
    if not store_ids:
        conn.close()
        return jsonify({"error": "No stores found for owner"}), 404

    placeholders = ",".join("?" * len(store_ids))

    # Date filter SQL snippet
    date_filter = ""
    params_date = []
    if date_from:
        date_filter += " AND date(timestamp) >= ? "
        params_date.append(date_from)
    if date_to:
        date_filter += " AND date(timestamp) <= ? "
        params_date.append(date_to)

    # Total units sold and revenue
    cursor.execute(f"""
        SELECT 
            IFNULL(SUM(quantity), 0), 
            IFNULL(SUM(total), 0)
        FROM sales
        WHERE product = ? AND store_id IN ({placeholders}) {date_filter}
    """, (product, *store_ids, *params_date))
    total_qty, total_revenue = cursor.fetchone()

    # Most popular price by quantity sold
    cursor.execute(f"""
        SELECT price, SUM(quantity) as qty_sold
        FROM sales
        WHERE product = ? AND store_id IN ({placeholders}) {date_filter}
        GROUP BY price
        ORDER BY qty_sold DESC
        LIMIT 1
    """, (product, *store_ids, *params_date))
    pop_price = cursor.fetchone()

    # Most expensive store price for the product
    cursor.execute(f"""
        SELECT store_id, price
        FROM inventory
        WHERE product = ? AND store_id IN ({placeholders})
        ORDER BY price DESC
        LIMIT 1
    """, (product, *store_ids))
    exp_store = cursor.fetchone()

    # Most lucrative store (highest sales revenue)
    cursor.execute(f"""
        SELECT store_id, SUM(total) as revenue
        FROM sales
        WHERE product = ? AND store_id IN ({placeholders}) {date_filter}
        GROUP BY store_id
        ORDER BY revenue DESC
        LIMIT 1
    """, (product, *store_ids, *params_date))
    best_store = cursor.fetchone()

    # Most sold product (by quantity) in all owner stores (for alerts)
    cursor.execute(f"""
        SELECT product, SUM(quantity) as total_sold
        FROM sales
        WHERE store_id IN ({placeholders}) {date_filter}
        GROUP BY product
        ORDER BY total_sold DESC
        LIMIT 1
    """, (*store_ids, *params_date))
    top_product = cursor.fetchone()

    # Profit margin = revenue - cost (approximate)
    # Sum cost * quantity from inventory joined to sales, approximate margin
    cursor.execute(f"""
        SELECT IFNULL(SUM(s.total - (i.cost * s.quantity)), 0)
        FROM sales s
        JOIN inventory i ON s.store_id = i.store_id AND s.product = i.product
        WHERE s.product = ? AND s.store_id IN ({placeholders}) {date_filter}
    """, (product, *store_ids, *params_date))
    profit_margin = cursor.fetchone()[0]

    # Price history for product
    cursor.execute(f"""
        SELECT store_id, old_price, new_price, change_percent, changed_on
        FROM price_history
        WHERE product = ? AND store_id IN ({placeholders})
        ORDER BY changed_on DESC
    """, (product, *store_ids))
    history_rows = cursor.fetchall()

    price_history = []
    for sid, old_price, new_price, change, changed_on in history_rows:
        price_history.append({
            "store_name": store_map.get(sid, "Unknown"),
            "old_price": old_price,
            "new_price": new_price,
            "change_percent": change,
            "changed_on": changed_on
        })

    kpis = {
        "Total Units Sold": total_qty,
        "Total Revenue": round(total_revenue, 2),
        "Most Popular Price": f"{pop_price[0]:.2f}" if pop_price else "N/A",
        "Most Expensive Store": store_map.get(exp_store[0], "N/A") if exp_store else "N/A",
        "Most Lucrative Store": store_map.get(best_store[0], "N/A") if best_store else "N/A",
        "Top Sold Product": top_product[0] if top_product else "N/A",
        "Profit Margin": round(profit_margin, 2)
    }

    conn.close()
    return jsonify({"kpis": kpis, "price_history": price_history})

@app.route("/compare_products", methods=["POST"])
def compare_products():
    data = request.get_json()
    owner_id = data.get("owner_id")
    products = data.get("products")  # list of product names
    date_from = data.get("date_from")
    date_to = data.get("date_to")

    if not owner_id or not products or not isinstance(products, list) or len(products) < 2:
        return jsonify({"error": "owner_id and at least 2 products required"}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT id, name FROM stores WHERE owner_id = ?", (owner_id,))
    stores = cursor.fetchall()
    store_map = {sid: sname for sid, sname in stores}
    store_ids = tuple(store_map.keys())
    if not store_ids:
        conn.close()
        return jsonify({"error": "No stores found for owner"}), 404

    placeholders = ",".join("?" * len(store_ids))
    date_filter = ""
    params_date = []
    if date_from:
        date_filter += " AND date(timestamp) >= ? "
        params_date.append(date_from)
    if date_to:
        date_filter += " AND date(timestamp) <= ? "
        params_date.append(date_to)

    results = {}
    for product in products:
        # Total quantity sold
        cursor.execute(f"""
            SELECT IFNULL(SUM(quantity), 0), IFNULL(SUM(total), 0)
            FROM sales
            WHERE product = ? AND store_id IN ({placeholders}) {date_filter}
        """, (product, *store_ids, *params_date))
        qty, total = cursor.fetchone()
        results[product] = {"total_sold": qty, "total_revenue": total}

    conn.close()
    return jsonify(results)

@app.route("/alerts", methods=["POST"])
def alerts():
    data = request.get_json()
    owner_id = data.get("owner_id")
    if not owner_id:
        return jsonify({"error": "owner_id missing"}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Example alert: products with price changes > 10% in last 30 days
    cursor.execute("""
        SELECT product, store_id, old_price, new_price, change_percent, changed_on
        FROM price_history
        WHERE changed_on >= date('now', '-30 day')
        AND ABS(change_percent) > 10
        AND store_id IN (SELECT id FROM stores WHERE owner_id = ?)
        ORDER BY changed_on DESC
    """, (owner_id,))

    alerts_list = []
    for row in cursor.fetchall():
        product, store_id, old_price, new_price, change_percent, changed_on = row
        alerts_list.append({
            "product": product,
            "store_name": (cursor.execute("SELECT name FROM stores WHERE id = ?", (store_id,)).fetchone() or ["Unknown"])[0],
            "old_price": old_price,
            "new_price": new_price,
            "change_percent": change_percent,
            "changed_on": changed_on
        })

    conn.close()
    return jsonify({"alerts": alerts_list})

@app.route('/import_inventory', methods=['POST'])
def import_inventory():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    store_id = request.form.get('store_id')
    if not store_id:
        return jsonify({"error": "Missing store_id"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        data = file.read()
        df = pd.read_excel(io.BytesIO(data))

        required_cols = {'product', 'quantity', 'cost', 'price'}
        if not required_cols.issubset(df.columns):
            return jsonify({"error": "Missing required columns"}), 400

        store_id_int = int(store_id)

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        for _, row in df.iterrows():
            product = str(row['product'])
            quantity = int(row['quantity'])
            cost = float(row['cost'])
            price = float(row['price'])

            # Upsert logic using store_id from POST form, not Excel
            cursor.execute('''SELECT id FROM inventory WHERE store_id=? AND product=?''', (store_id_int, product))
            result = cursor.fetchone()
            if result:
                inventory_id = result[0]
                cursor.execute('''
                    UPDATE inventory
                    SET quantity=?, cost=?, price=?
                    WHERE id=?
                ''', (quantity, cost, price, inventory_id))
            else:
                cursor.execute('''
                    INSERT INTO inventory (store_id, product, quantity, cost, price)
                    VALUES (?, ?, ?, ?, ?)
                ''', (store_id_int, product, quantity, cost, price))

        conn.commit()
        conn.close()
        return jsonify({"message": "Inventory imported successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/export_product_data", methods=["POST"])
def export_product_data():
    data = request.get_json()
    owner_id = data.get("owner_id")
    product = data.get("product")
    date_from = data.get("date_from")
    date_to = data.get("date_to")
    export_format = data.get("format", "csv")  # csv or json

    if not owner_id or not product:
        return jsonify({"error": "owner_id or product missing"}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Get sales data with optional date filter
    date_filter = ""
    params_date = []
    if date_from:
        date_filter += " AND date(timestamp) >= ? "
        params_date.append(date_from)
    if date_to:
        date_filter += " AND date(timestamp) <= ? "
        params_date.append(date_to)

    cursor.execute(f"""
        SELECT timestamp, store_id, quantity, price, total
        FROM sales
        WHERE product = ? AND store_id IN (SELECT id FROM stores WHERE owner_id = ?) {date_filter}
        ORDER BY timestamp ASC
    """, (product, owner_id, *params_date))

    rows = cursor.fetchall()
    conn.close()

    if export_format == "json":
        data_export = [{
            "timestamp": r[0],
            "store_id": r[1],
            "quantity": r[2],
            "price": r[3],
            "total": r[4]
        } for r in rows]
        return jsonify(data_export)

    # Default to CSV export
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "store_id", "quantity", "price", "total"])
    writer.writerows(rows)
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        attachment_filename=f"{product}_sales_export.csv"
    )

@app.route('/export_sales')
def export_sales():
    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT timestamp, product, quantity, price, total, discount, payment_method,
               edited, edit_time, receipt_id, log, editor
        FROM sales
    """)
    rows = cursor.fetchall()
    conn.close()

    def generate():
        # CSV headers with new columns
        yield "Date,Product,Quantity,Price (MAD),Total (MAD),Discount (MAD),Payment Method,Edited,Edit Time,Receipt ID,Log,Editor\n"
        for row in rows:
            # Wrap each field in quotes, escape inner quotes, handle None gracefully
            line = ",".join(
                '"{}"'.format(str(col).replace('"', '""')) if col is not None else '""'
                for col in row
            )
            yield line + "\n"

    return Response(
        generate(),
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=sales_history.csv"}
    )

@app.route("/get_busy_hours", methods=["POST"])
def get_busy_hours():
    data = request.json
    store_id = data["store_id"]
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp FROM sales WHERE store_id=?", (store_id,))
        hours = [datetime.fromisoformat(row[0]).hour for row in cursor.fetchall() if row[0]]
        count = dict(Counter(hours))
    return jsonify(count)

@app.route("/add_credit", methods=["POST"])
def add_credit():
    data = request.get_json()
    store_id = data.get("store_id")
    client = data.get("client")
    tab_value = data.get("tab_value")
    total = data.get("total")
    user_id = data.get("user_id")  # This must be a WORKER ID

    if not all([store_id, client, tab_value is not None, total is not None, user_id]):
        return jsonify({"error": "Missing fields"}), 400

    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()

    # Confirm the user_id is from workers table
    cursor.execute("SELECT id FROM workers WHERE id = ?", (user_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "Invalid worker ID"}), 400

    tab_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "Unpaid"

    cursor.execute("""
        INSERT INTO credits (store_id, client, tab_value, total, user_id, tab_date, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (store_id, client, tab_value, total, user_id, tab_date, status))

    conn.commit()
    conn.close()
    return jsonify({"message": "Credit added successfully."})

@app.route("/get_credits", methods=["POST"])
def get_credits():
    data = request.get_json()
    store_id = data.get("store_id")

    if not store_id:
        return jsonify({"error": "Missing store ID"}), 400

    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT credits.client, credits.tab_value, credits.tab_date,
               workers.username AS worker_username,
               credits.status
        FROM credits
        LEFT JOIN workers ON credits.user_id = workers.id
        WHERE credits.store_id = ? AND credits.status IN ('Unpaid', 'Pending')
        ORDER BY credits.tab_date DESC
    """, (store_id,))

    rows = cursor.fetchall()
    conn.close()

    credits = [{
        "client": row[0],
        "tab_value": row[1],
        "tab_date": row[2],
        "worker_username": row[3],
        "status": row[4]
    } for row in rows]

    return jsonify(credits)

@app.route("/pay_credit", methods=["POST"])
def pay_credit():
    data = request.get_json()
    store_id = data.get("store_id")
    client = data.get("client")
    amount = float(data.get("amount"))

    if not all([store_id, client, amount]):
        return jsonify({"error": "Missing fields"}), 400

    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, tab_value, total FROM credits
        WHERE store_id = ? AND client = ? AND status = 'Unpaid'
        ORDER BY tab_date ASC
    """, (store_id, client))
    rows = cursor.fetchall()

    if not rows:
        conn.close()
        return jsonify({"error": "No unpaid tab found"}), 404

    for credit_id, tab_value, total in rows:
        if amount <= 0:
            break

        applied = min(tab_value, amount)
        new_tab_value = tab_value - applied
        new_total = total - applied
        amount -= applied

        if new_tab_value <= 0:
            cursor.execute("""
                UPDATE credits
                SET tab_value = 0, total = ?, status = 'Paid', payment_date = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (max(0, new_total), credit_id))
        else:
            cursor.execute("""
                UPDATE credits
                SET tab_value = ?, total = ?, payment_date = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (new_tab_value, max(0, new_total), credit_id))

    conn.commit()
    conn.close()
    return jsonify({"message": "Payment processed"})

@app.route("/owner_inventory", methods=["GET"])
def get_owner_inventory():
    store_id = request.args.get("store_id")
    if not store_id:
        return jsonify({"error": "Missing store_id"}), 400

    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, product, quantity, cost, price FROM inventory WHERE store_id = ?", (store_id,))
    rows = cursor.fetchall()
    conn.close()

    inventory = [{"id": r[0], "product": r[1], "quantity": r[2], "cost": r[3], "price": r[4]} for r in rows]
    return jsonify({"inventory": inventory})


@app.route("/update_inventory_owner", methods=["POST"])
def update_inventory_owner():
    data = request.get_json()
    store_id = data.get("store_id")
    inventory_id = data.get("id")
    product = data.get("product")
    quantity = data.get("quantity")

    if not all([store_id, inventory_id]):
        return jsonify({"error": "Missing fields"}), 400

    conn = sqlite3.connect("smartbiz.db")
    c = conn.cursor()

    c.execute("""
        UPDATE inventory
        SET product = ?, quantity = ?
        WHERE id = ? AND store_id = ?
    """, (product, quantity, inventory_id, store_id))

    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route("/update_inventory_worker", methods=["POST"])
def update_inventory_worker():
    data = request.get_json()
    store_id = data.get("store_id")
    product = data.get("product")
    quantity = data.get("quantity")

    if not all([store_id, product, quantity is not None]):
        return jsonify({"error": "Missing fields"}), 400

    conn = sqlite3.connect("smartbiz.db")
    c = conn.cursor()

    c.execute("SELECT id, quantity FROM inventory WHERE store_id = ? AND product = ?", (store_id, product))
    result = c.fetchone()
    if not result:
        conn.close()
        return jsonify({"error": "Product not found in this store"}), 404

    inventory_id, current_qty = result

    # Optional: prevent going negative
    if current_qty + quantity < 0:
        conn.close()
        return jsonify({"error": "❌ Not enough stock to remove that many items."}), 400

    c.execute("""
        UPDATE inventory
        SET quantity = quantity + ?
        WHERE id = ?
    """, (quantity, inventory_id))

    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"✅ Updated {product} stock to {current_qty + quantity}"})

@app.route("/search_inventory", methods=["POST"])
def search_inventory():
    data = request.get_json()
    store_id = data.get("store_id")
    query = data.get("query", "").strip()

    if not store_id or not query:
        return jsonify({"error": "Missing store_id or query"}), 400

    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()

    # Search by product name or barcode (barcode column assumed; if missing, remove barcode part)
    cursor.execute("""
        SELECT id, product, quantity, cost, price
        FROM inventory
        WHERE store_id = ?
          AND (product LIKE ?)
        LIMIT 20
    """, (store_id, f"%{query}%"))

    rows = cursor.fetchall()
    conn.close()

    results = [
        {"id": r[0], "product": r[1], "quantity": r[2], "cost": r[3], "price": r[4]}
        for r in rows
    ]
    return jsonify(results)

@app.route("/manage_inventory", methods=["POST"])
def manage_inventory():
    data = request.get_json()
    store_id = data.get("store_id")
    product = data.get("product")
    quantity = data.get("quantity")
    cost = data.get("cost")
    price = data.get("price")

    if not all([store_id, product, quantity is not None, cost is not None, price is not None]):
        return jsonify({"error": "Missing fields"}), 400

    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()

    # Check if product exists
    cursor.execute("SELECT id, price FROM inventory WHERE store_id = ? AND product = ?", (store_id, product))
    existing = cursor.fetchone()

    if existing:
        product_id, old_price = existing

        if old_price != price:
            # Calculate percent change
            try:
                change_percent = ((price - old_price) / old_price) * 100 if old_price != 0 else 0
            except ZeroDivisionError:
                change_percent = 0

            # Log price change
            cursor.execute('''
                INSERT INTO price_history (store_id, product, old_price, new_price, change_percent)
                VALUES (?, ?, ?, ?, ?)
            ''', (store_id, product, old_price, price, change_percent))

        # Update inventory
        cursor.execute("""
            UPDATE inventory
            SET quantity = ?, cost = ?, price = ?
            WHERE store_id = ? AND product = ?
        """, (quantity, cost, price, store_id, product))

    else:
        cursor.execute("""
            INSERT INTO inventory (store_id, product, quantity, cost, price)
            VALUES (?, ?, ?, ?, ?)
        """, (store_id, product, quantity, cost, price))

    conn.commit()
    conn.close()
    return jsonify({"message": "✅ Inventory updated"})

@app.route("/delete_inventory", methods=["POST"])
def delete_inventory():
    data = request.get_json()
    store_id = data.get("store_id")
    product = data.get("product")
    if not all([store_id, product]):
        return jsonify({"error": "Missing fields"}), 400

    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM inventory WHERE store_id = ? AND product = ?", (store_id, product))
    conn.commit()
    conn.close()

    return jsonify({"message": "🗑️ Product deleted"})

def get_user_by_username(username):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()

def ensure_user_settings_columns():
    """Run once on app startup to add columns if missing."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # Map of column name => type
        columns_to_add = {
            "language": "TEXT",
            "theme": "TEXT",
            "high_contrast": "TEXT DEFAULT 'false'",
            "font_size": "TEXT"
        }
        cursor.execute("PRAGMA table_info(users)")
        existing_columns = {row[1] for row in cursor.fetchall()}
        for col, col_type in columns_to_add.items():
            if col not in existing_columns:
                try:
                    cursor.execute(f"ALTER TABLE users ADD COLUMN {col} {col_type}")
                except sqlite3.OperationalError:
                    pass
        conn.commit()

# Call once at startup
ensure_user_settings_columns()

@app.route('/settings/change_password', methods=['POST'])
def change_password():
    data = request.get_json()
    username = data.get("username")
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not username or not old_password or not new_password:
        return jsonify({"error": "Missing required fields"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    hashed_password = user[2]  # Assuming password is in index 2
    if not check_password_hash(hashed_password, old_password):
        return jsonify({"error": "Old password incorrect"}), 403

    new_hash = generate_password_hash(new_password)
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_hash, username))
        conn.commit()

    return jsonify({"success": True, "message": "Password updated"})

@app.route('/settings/update_email', methods=['POST'])
def update_email():
    data = request.get_json()
    username = data.get("username")
    new_email = data.get("email")

    if not username or not new_email:
        return jsonify({"error": "Missing required fields"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET email = ? WHERE username = ?", (new_email, username))
        conn.commit()

    return jsonify({"success": True, "message": "Email updated"})

@app.route('/settings/update_phone', methods=['POST'])
def update_phone():
    data = request.get_json()
    username = data.get("username")
    new_phone = data.get("phone")

    if not username or not new_phone:
        return jsonify({"error": "Missing required fields"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET phone = ? WHERE username = ?", (new_phone, username))
        conn.commit()

    return jsonify({"success": True, "message": "Phone updated"})

@app.route('/settings/upload_profile_image', methods=['POST'])
def upload_profile_image():
    username = request.form.get('username')
    file = request.files.get('image')

    if not username or not file:
        return jsonify({"error": "Username and image file required"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    filename = secure_filename(username) + ".png"  # Save as PNG named by username
    filepath = os.path.join(PROFILE_IMG_FOLDER, filename)
    try:
        file.save(filepath)
    except Exception as e:
        return jsonify({"error": f"Failed to save image: {str(e)}"}), 500

    # Return relative URL for frontend display
    url = f"/{PROFILE_IMG_FOLDER}/{filename}"
    return jsonify({"success": True, "url": url})

@app.route('/settings/set_language', methods=['POST'])
def set_language():
    data = request.get_json()
    username = data.get("username")
    language = data.get("language")

    if not username or not language:
        return jsonify({"error": "Missing required fields"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET language = ? WHERE username = ?", (language, username))
        conn.commit()

    return jsonify({"success": True, "message": "Language updated"})

@app.route('/settings/set_theme', methods=['POST'])
def set_theme():
    data = request.get_json()
    username = data.get("username")
    theme = data.get("theme")

    if not username or not theme:
        return jsonify({"error": "Missing required fields"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET theme = ? WHERE username = ?", (theme, username))
        conn.commit()

    return jsonify({"success": True, "message": "Theme updated"})

@app.route('/settings/set_accessibility', methods=['POST'])
def set_accessibility():
    data = request.get_json()
    username = data.get("username")
    high_contrast = data.get("high_contrast")  # Expect 'true' or 'false'
    font_size = data.get("font_size")          # Expect string like '16px'

    if not username:
        return jsonify({"error": "Missing username"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        if high_contrast is not None:
            cursor.execute("UPDATE users SET high_contrast = ? WHERE username = ?", (high_contrast, username))
        if font_size is not None:
            cursor.execute("UPDATE users SET font_size = ? WHERE username = ?", (font_size, username))
        conn.commit()

    return jsonify({"success": True, "message": "Accessibility settings updated"})

# ----------- OWNER PROFILE -----------

@app.route("/owner/profile")
def owner_profile_page():
    return send_from_directory("Owner", "profile.html")


@app.route("/api/owner/profile/<int:user_id>", methods=["GET"])
def get_owner_profile(user_id):
    with sqlite3.connect("smartbiz.db") as conn:
        c = conn.cursor()
        c.execute("""
            SELECT username, email, phone, ice, role, language, theme,
                   high_contrast, font_size, profile_pic
            FROM users
            WHERE id=?
        """, (user_id,))
        row = c.fetchone()

    if not row:
        return jsonify({"error": "Owner not found"}), 404

    (username, email, phone, ice, role, language, theme,
     high_contrast, font_size, profile_pic) = row

    # No created_at column for owners → fallback
    duration = "-"

    return jsonify({
        "username": username or "",
        "email": email or "",
        "phone": phone or "",
        "ice": ice or "",
        "role": role or "",
        "language": language or "en",
        "theme": theme or "light",
        "high_contrast": high_contrast or "off",
        "font_size": font_size or "medium",
        "duration": duration,
        "profile_pic": profile_pic or "/static/profile_images/default_profile.jpg"
    })



@app.route("/api/owner/profile/update", methods=["POST"])
def update_owner_profile():
    data = request.get_json()
    user_id = data.get("user_id")
    username = data.get("username") or ""
    email = data.get("email") or ""
    phone = data.get("phone") or ""
    ice = data.get("ice") or ""
    language = data.get("language") or "en"
    theme = data.get("theme") or "light"
    high_contrast = data.get("high_contrast") or "off"
    font_size = data.get("font_size") or "medium"
    password = data.get("password")

    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    with sqlite3.connect("smartbiz.db") as conn:
        c = conn.cursor()
        if password:
            c.execute("""
                UPDATE users
                SET username=?, email=?, phone=?, ice=?, language=?, theme=?, 
                    high_contrast=?, font_size=?, password=?
                WHERE id=?
            """, (username, email, phone, ice, language, theme, high_contrast, font_size, password, user_id))
        else:
            c.execute("""
                UPDATE users
                SET username=?, email=?, phone=?, ice=?, language=?, theme=?, 
                    high_contrast=?, font_size=?
                WHERE id=?
            """, (username, email, phone, ice, language, theme, high_contrast, font_size, user_id))
        conn.commit()

    return jsonify({"success": True})


@app.route("/api/owner/profile/pic", methods=["POST"])
def update_owner_pic():
    user_id = request.form.get("user_id")
    file = request.files.get("image")
    if not user_id or not file:
        return jsonify({"error": "Missing user_id or file"}), 400

    filename = secure_filename(file.filename)
    save_path = os.path.join("static", "uploads", filename)
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    file.save(save_path)

    web_path = f"/static/uploads/{filename}"

    with sqlite3.connect("smartbiz.db") as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET profile_pic=? WHERE id=?", (web_path, user_id))
        conn.commit()

    return jsonify({"success": True, "new_path": web_path})

# ----------- WORKER PROFILE -----------

@app.route("/profile")
def profile_page():
    return send_from_directory("Worker", "profile.html")

@app.route("/api/worker/profile/<int:worker_id>", methods=["GET"])
def get_worker_profile(worker_id):
    with sqlite3.connect("smartbiz.db") as conn:
        c = conn.cursor()
        c.execute("""
            SELECT name, lastname, username, email, created_at, profile_pic
            FROM workers
            WHERE id=?
        """, (worker_id,))
        row = c.fetchone()

    if not row:
        return jsonify({"error": "Worker not found"}), 404

    name, lastname, username, email, created_at, profile_pic = row
    try:
        created_dt = datetime.fromisoformat(created_at)
        duration = f"{(datetime.now() - created_dt).days} days"
    except:
        duration = "-"

    return jsonify({
        "name": name or "",
        "lastname": lastname or "",
        "email": email or "",
        "username": username or "",
        "duration": duration,
        "profile_pic": profile_pic or "/static/profile_images/default_profile.png"
    })

@app.route("/api/worker/profile/update", methods=["POST"])
def update_worker_profile():
    data = request.get_json()
    worker_id = data.get("user_id")
    name = data.get("name") or ""
    lastname = data.get("lastname") or ""
    email = data.get("email") or ""
    password = data.get("password")

    if not worker_id:
        return jsonify({"error": "Missing user_id"}), 400

    with sqlite3.connect("smartbiz.db") as conn:
        c = conn.cursor()
        if password:
            c.execute("""
                UPDATE workers
                SET name=?, lastname=?, email=?, password=?
                WHERE id=?
            """, (name, lastname, email, password, worker_id))
        else:
            c.execute("""
                UPDATE workers
                SET name=?, lastname=?, email=?
                WHERE id=?
            """, (name, lastname, email, worker_id))
        conn.commit()

    return jsonify({"success": True})

@app.route("/api/worker/profile/pic", methods=["POST"])
def update_worker_pic():
    worker_id = request.form.get("user_id")
    file = request.files.get("image")
    if not worker_id or not file:
        return jsonify({"error": "Missing user_id or file"}), 400

    filename = secure_filename(file.filename)
    save_path = os.path.join("static", "uploads", filename)
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    file.save(save_path)

    # Always store normalized web path (with forward slashes)
    web_path = f"/static/uploads/{filename}"

    with sqlite3.connect("smartbiz.db") as conn:
        c = conn.cursor()
        c.execute("UPDATE workers SET profile_pic=? WHERE id=?", (web_path, worker_id))
        conn.commit()

    return jsonify({"success": True, "new_path": web_path})

@app.route("/api/worker/performance/<int:worker_id>", methods=["GET"])
def worker_performance(worker_id):
    try:
        with sqlite3.connect("smartbiz.db") as conn:
            c = conn.cursor()

            # Total sales and total products sold
            c.execute("SELECT IFNULL(SUM(total),0), IFNULL(SUM(quantity),0) FROM sales WHERE user_id=?", (worker_id,))
            total_sales_mad, total_products = c.fetchone()

            # Best day (highest total) based on timestamp date
            c.execute("""
                SELECT DATE(timestamp) as day, SUM(total) as day_total
                FROM sales
                WHERE user_id=?
                GROUP BY day
                ORDER BY day_total DESC
                LIMIT 1
            """, (worker_id,))
            best_day_row = c.fetchone()
            best_day = best_day_row[0] if best_day_row else "-"

            # Best month (highest total) based on year-month
            c.execute("""
                SELECT STRFTIME('%Y-%m', timestamp) as month, SUM(total) as month_total
                FROM sales
                WHERE user_id=?
                GROUP BY month
                ORDER BY month_total DESC
                LIMIT 1
            """, (worker_id,))
            best_month_row = c.fetchone()
            best_month = best_month_row[0] if best_month_row else "-"

            # Top 10 products by quantity sold
            c.execute("""
                SELECT product, SUM(quantity) as total_qty
                FROM sales
                WHERE user_id=?
                GROUP BY product
                ORDER BY total_qty DESC
                LIMIT 10
            """, (worker_id,))
            top_products = [{"product_name": r[0], "total": r[1]} for r in c.fetchall()]

        return jsonify({
            "total_sales_mad": total_sales_mad,
            "total_products": total_products,
            "best_day": best_day,
            "best_month": best_month,
            "top_products": top_products
        })

    except Exception as e:
        print("❌ Error in /performance route:", e)
        return jsonify({"error": "Failed to fetch performance"}), 500

#======================================///

#======  OWNER STAFF ========

@app.route("/api/staff", methods=["GET"])
def get_staff():
    owner_id = request.args.get("owner_id")
    store_id = request.args.get("store_id")  # optional filter by store

    if not owner_id:
        return jsonify({"error": "Missing owner_id"}), 400

    conn = sqlite3.connect("smartbiz.db")
    cursor = conn.cursor()

    try:
        # Base query: only workers of stores belonging to this owner
        query = """
            SELECT w.id, w.username, w.name, w.lastname, w.email, 
                   s.name AS store_name, w.profile_pic, w.created_at,
                   IFNULL(SUM(sa.total), 0) AS earnings
            FROM workers w
            INNER JOIN stores s ON w.store_id = s.id
            LEFT JOIN sales sa ON sa.user_id = w.id
            WHERE s.owner_id = ?
        """
        params = [owner_id]

        # Optional: filter by a specific store
        if store_id and store_id != "all":
            query += " AND w.store_id = ?"
            params.append(store_id)

        query += " GROUP BY w.id, w.username, w.name, w.lastname, w.email, s.name, w.profile_pic, w.created_at"

        cursor.execute(query, params)

        staff = [
            {
                "id": row[0],
                "username": row[1],
                "name": row[2],
                "lastname": row[3],
                "email": row[4],
                "store_name": row[5],
                "profile_pic": row[6] or "default.png",
                "created_at": row[7],
                "earnings": row[8]
            }
            for row in cursor.fetchall()
        ]
        return jsonify(staff)

    except Exception as e:
        print("Error in /api/staff:", e)
        return jsonify({"error": "Failed to fetch staff"}), 500
    finally:
        conn.close()


# ================= CHAT FUNCTION =================
user_rooms = {}        # sid -> room
connected_users = {}   # sid -> {"user_id": ..., "role": ...}

def _ensure_chat_table():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL,
                sender_type TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now'))
            )
        """)
        conn.commit()
_ensure_chat_table()

# ----------------- AUTH HELPERS -----------------
def get_user_from_token():
    token = None
    if request.args.get("token"):
        token = request.args.get("token")
    elif request.json and request.json.get("token"):
        token = request.json.get("token")
    elif hasattr(request, "namespace") and request.namespace and request.namespace.auth:
        token = request.namespace.auth.get("token")

    if not token:
        return None
    try:
        parts = token.split(":")
        return {"user_id": int(parts[0]), "role": parts[1]}
    except:
        return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_user_from_token()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        request.user = user
        return f(*args, **kwargs)
    return decorated_function

def _row_to_worker_dict(row, role="worker"):
    return {
        "id": row["id"],
        "name": row.get("name") or row.get("username"),
        "profile_pic": row.get("profile_pic") or "/static/profile_images/default_profile.png",
        "username": f"{role}:{row['id']}"   # <-- added
    }


def get_room_name(user1, user2):
    """Stable room name: user1 and user2 must be role:id strings."""
    u_min, u_max = sorted([str(user1), str(user2)])
    return f"chat_{u_min}_{u_max}"

@app.route("/get_contacts")
@login_required
def get_contacts():
    user = request.user
    user_id = user["user_id"]
    role = user["role"]

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if role == "owner":
        cursor.execute("SELECT id, name FROM stores WHERE owner_id=?", (user_id,))
        stores = cursor.fetchall()
        result = []
        for s in stores:
            store_id = s["id"]
            store_name = s["name"]
            cursor.execute("SELECT id, username as name, profile_pic FROM workers WHERE store_id=?", (store_id,))
            workers = [_row_to_worker_dict(dict(w), role="worker") for w in cursor.fetchall()]
            result.append({"store_id": store_id, "store_name": store_name, "workers": workers})
        return jsonify(result)

    elif role == "worker":
        cursor.execute("SELECT store_id FROM workers WHERE id=?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify([])
        store_id = row["store_id"]

        cursor.execute("SELECT id, name, owner_id FROM stores WHERE id=?", (store_id,))
        store_row = cursor.fetchone()
        if not store_row:
            return jsonify([])
        store_name = store_row["name"]
        owner_id = store_row["owner_id"]

        cursor.execute("SELECT id, username as name, profile_pic FROM workers WHERE store_id=?", (store_id,))
        coworkers = [_row_to_worker_dict(dict(w)) for w in cursor.fetchall()]

        cursor.execute("SELECT id, username as name, profile_pic FROM users WHERE id=?", (owner_id,))
        o = cursor.fetchone()
        owner_info = {"id": o["id"], "name": o["name"],
                      "profile_pic": o["profile_pic"] or "/static/profile_images/default_profile.png",
                      "username": f"owner:{o['id']}"} if o else None

        workers_list = [owner_info] if owner_info else []
        workers_list.extend(coworkers)

        return jsonify([{
            "store_id": store_id,
            "store_name": store_name,
            "current_worker_id": int(user_id),
            "workers": workers_list
        }])
# ----------------- CHAT HISTORY -----------------
@app.route("/get_chat_history/<string:other_id>", methods=["GET"])
@login_required
def get_chat_history(other_id):
    # Ensure other_id is role:id string
    if ":" not in other_id:
        role = "worker" if request.user["role"] == "owner" else "owner"
        other_id = f"{role}:{other_id}"

    user_id = f'{request.user["role"]}:{request.user["user_id"]}'
    room = get_room_name(user_id, other_id)
    print(f"Fetching chat history for room: {room}")  # DEBUG

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sender_id, sender_type, message, timestamp
        FROM chat_messages
        WHERE chat_id = ?
        ORDER BY timestamp ASC
    """, (room,))
    rows = cursor.fetchall()
    conn.close()

    history = [
        {"sender_id": r["sender_id"], "sender_type": r["sender_type"], "message": r["message"], "timestamp": r["timestamp"]}
        for r in rows
    ]
    return jsonify(history)

# ----------------- SOCKETIO -----------------

@socketio.on("connect")
def on_connect(auth):
    token = auth.get("token")
    if not token:
        return False
    try:
        user_id, role = token.split(":")
        user = {"user_id": int(user_id), "role": role}
        connected_users[request.sid] = user
        print(f"✅ User {user_id} connected via socket ({role})")
    except:
        return False

@socketio.on("disconnect")
def on_disconnect():
    user = connected_users.pop(request.sid, None)
    room = user_rooms.pop(request.sid, None)
    if user:
        print(f"User {user['user_id']} disconnected")
        if room:
            leave_room(room)
@socketio.on("join_room")
def on_join(data):
    room = data.get("room")
    user = connected_users.get(request.sid)
    if room and user:
        join_room(room)
        user_rooms[request.sid] = room
        emit("receive_message", {"user": "System", "message": f"User {user['role']}:{user['user_id']} joined room {room}"}, room=room)

@socketio.on("send_message")
def on_message(data):
    room = data.get("room")
    msg = data.get("message")
    msg_type = data.get("type", "text")

    user = connected_users.get(request.sid)
    if user:
        sender_id = f'{user["role"]}:{user["user_id"]}'
        sender_type = user["role"]
    else:
        sender_id = data.get("sender_id") or "unknown"
        sender_type = data.get("sender_type") or "unknown"

    if not (room and msg and sender_id):
        print("Message rejected: missing room, msg, or sender info")
        return

    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO chat_messages (chat_id, sender_type, sender_id, message) VALUES (?,?,?,?)",
            (room, sender_type, sender_id, msg)
        )
        conn.commit()
        last_id = cur.lastrowid
        cur.execute("SELECT timestamp FROM chat_messages WHERE id = ?", (last_id,))
        ts_row = cur.fetchone()
        timestamp = ts_row["timestamp"] if ts_row else None

    emit("receive_message", {
        "user": sender_id,
        "sender_type": sender_type,
        "message": msg,
        "type": msg_type,
        "timestamp": timestamp
    }, room=room)

@socketio.on("typing")
def handle_typing(data):
    user = connected_users.get(request.sid)
    recipient_id = data.get("recipient_id")
    if not user or not recipient_id:
        return
    if ":" not in str(recipient_id):
        recipient_id = f"{'worker' if user['role']=='owner' else 'owner'}:{recipient_id}"
    room = get_room_name(f'{user["role"]}:{user["user_id"]}', recipient_id)
    emit("typing", {"sender_id": f'{user["role"]}:{user["user_id"]}'}, room=room, include_self=False)

@socketio.on("stop_typing")
def handle_stop_typing(data):
    user = connected_users.get(request.sid)
    recipient_id = data.get("recipient_id")
    if not user or not recipient_id:
        return
    if ":" not in str(recipient_id):
        recipient_id = f"{'worker' if user['role']=='owner' else 'owner'}:{recipient_id}"
    room = get_room_name(f'{user["role"]}:{user["user_id"]}', recipient_id)
    emit("stop_typing", {"sender_id": f'{user["role"]}:{user["user_id"]}'}, room=room, include_self=False)

if __name__ == "__main__":
    import os
    try:
        from gevent import pywsgi
        from geventwebsocket.handler import WebSocketHandler
    except Exception as e:
        print("gevent/geventwebsocket not available, falling back to Flask dev server. Error:", e)
        port = int(os.environ.get("PORT", 5000))
        app.run(host="0.0.0.0", port=port)
    else:
        port = int(os.environ.get("PORT", 5000))
        http_server = pywsgi.WSGIServer(("0.0.0.0", port), app, handler_class=WebSocketHandler)
        print(f"Starting local gevent WSGI server on port {port}")
        http_server.serve_forever()
