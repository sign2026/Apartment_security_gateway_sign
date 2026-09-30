from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import Optional, List
import sqlite3
import hashlib
app = FastAPI(title="Apartment Security System API") 
@app.get("/")
def read_root():
    return {"message": "Apartment Security System API is running"}
# DB Initialization
def init_db():
    conn = sqlite3.connect("apartment_security.db")
    cursor = conn.cursor()
    # Resident / User Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mobile TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            block TEXT NOT NULL,
            door_no TEXT NOT NULL,
            area TEXT NOT NULL,
            pincode TEXT NOT NULL,
            role TEXT CHECK(role IN ('RESIDENT', 'SECURITY', 'SUPER_ADMIN')) NOT NULL,
            is_approved INTEGER DEFAULT 0
        )
    ''')
    # Visitors Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS visitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mobile TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            company TEXT,
            purpose TEXT NOT NULL,
            vehicle_no TEXT,
            photo_url TEXT,
            door_no TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING'
        )
    ''')
    # Banners Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS banners (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            image_url TEXT NOT NULL,
            target_audience TEXT CHECK(target_audience IN ('ALL', 'RESIDENT', 'SECURITY')) NOT NULL,
            area TEXT,
            language TEXT DEFAULT 'TAMIL',
            action_type TEXT CHECK(action_type IN ('CALL', 'BOOKING', 'WHATSAPP')),
            action_value TEXT
        )
    ''')
    conn.commit()
    conn.close()
init_db()
# Models
class ResidentRegister(BaseModel):
    mobile: str
    password: str
    block: str
    door_no: str
    area: str
    pincode: str
    role: str = "RESIDENT"
class VisitorEntry(BaseModel):
    mobile: str
    name: str
    company: Optional[str] = None
    purpose: str
    vehicle_no: Optional[str] = None
    photo_url: str
    door_no: str
# Helper Function
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()
# Endpoints
@app.post("/register")
def register_user(user: ResidentRegister):
    conn = sqlite3.connect("apartment_security.db")
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (mobile, password_hash, block, door_no, area, pincode, role) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user.mobile, hash_password(user.password), user.block, user.door_no, user.area, user.pincode, user.role)
        )
        conn.commit()
        return {"status": "Success", "message": "User registered. Waiting for admin/security approval."}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Mobile number already exists (Duplicate Entry Prevention).")
    finally:
        conn.close()
@app.post("/visitor/entry")
def add_visitor(visitor: VisitorEntry):
    conn = sqlite3.connect("apartment_security.db")
    cursor = conn.cursor()
    # Check if visitor already registered (no re-photo required logically handled in UI)
    cursor.execute("SELECT id FROM visitors WHERE mobile = ?", (visitor.mobile,))
    existing = cursor.fetchone()
    if existing:
        cursor.execute(
            "UPDATE visitors SET purpose=?, vehicle_no=?, door_no=?, status='PENDING' WHERE mobile=?",
            (visitor.purpose, visitor.vehicle_no, visitor.door_no, visitor.mobile)
        )
    else:
        cursor.execute(
            "INSERT INTO visitors (mobile, name, company, purpose, vehicle_no, photo_url, door_no) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (visitor.mobile, visitor.name, visitor.company, visitor.purpose, visitor.vehicle_no, visitor.photo_url, visitor.door_no)
        )
    conn.commit()
    conn.close()
    return {"status": "Success", "message": "Visitor added and notification sent to Resident."}
@app.get("/banners/{audience}")
def get_banners(audience: str, area: Optional[str] = None):
    conn = sqlite3.connect("apartment_security.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM banners WHERE target_audience IN ('ALL', ?) OR area=?", (audience, area))
    rows = cursor.fetchall()
    conn.close()
    return {"banners": rows}
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)