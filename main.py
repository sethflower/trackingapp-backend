"""
TrackingApp Backend — FastAPI + PostgreSQL (для Render.com)
"""

import os
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor

# Render.com сам даёт переменную DATABASE_URL
DATABASE_URL = os.getenv("DATABASE_URL", "")

app = FastAPI(title="TrackingApp API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn


# === Автосоздание таблиц при первом запуске ===
@app.on_event("startup")
def create_tables():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            last_name VARCHAR(100) NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(20) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS scan_records (
            id SERIAL PRIMARY KEY,
            box_id VARCHAR(100) NOT NULL,
            ttn VARCHAR(100) NOT NULL,
            user_last_name VARCHAR(100) NOT NULL,
            scanned_at TIMESTAMP NOT NULL,
            note VARCHAR(255) DEFAULT 'ok',
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_scan_box_id ON scan_records(box_id);
        CREATE INDEX IF NOT EXISTS idx_scan_ttn ON scan_records(ttn);
        CREATE INDEX IF NOT EXISTS idx_scan_date ON scan_records(scanned_at);
    """)
    # Создать админа если его нет
    cur.execute("SELECT id FROM users WHERE last_name = 'Admin'")
    if not cur.fetchone():
        cur.execute("INSERT INTO users (last_name, password, role) VALUES ('Admin', 'admin123', 'admin')")
    conn.commit()
    cur.close()
    conn.close()


# ========== МОДЕЛИ ==========
class RegisterRequest(BaseModel):
    last_name: str
    password: str

class LoginRequest(BaseModel):
    last_name: str
    password: str

class AdminLoginRequest(BaseModel):
    last_name: str
    admin_password: str

class UpdateUserRequest(BaseModel):
    last_name: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None

class ScanRequest(BaseModel):
    box_id: str
    ttn: str
    user_last_name: str
    scanned_at: str

class ScanBatchRequest(BaseModel):
    records: List[ScanRequest]


# ========== АВТОРИЗАЦИЯ ==========

@app.post("/api/register")
def register(req: RegisterRequest):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE last_name = %s", (req.last_name,))
        if cur.fetchone():
            raise HTTPException(400, "Пользователь с такой фамилией уже существует")
        cur.execute(
            "INSERT INTO users (last_name, password, role) VALUES (%s, %s, 'pending')",
            (req.last_name, req.password)
        )
        conn.commit()
        return {"message": "Регистрация успешна. Ожидайте подтверждения администратора."}
    finally:
        cur.close()
        conn.close()


@app.post("/api/login")
def login(req: LoginRequest):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, last_name, role FROM users WHERE last_name = %s AND password = %s",
            (req.last_name, req.password)
        )
        user = cur.fetchone()
        if not user:
            raise HTTPException(401, "Неверная фамилия или пароль")
        if user["role"] == "pending":
            raise HTTPException(403, "Ваш аккаунт ещё не подтверждён администратором")
        return {"id": user["id"], "last_name": user["last_name"], "role": user["role"]}
    finally:
        cur.close()
        conn.close()


@app.post("/api/admin/login")
def admin_login(req: AdminLoginRequest):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, last_name, role FROM users WHERE last_name = %s AND password = %s AND role = 'admin'",
            (req.last_name, req.admin_password)
        )
        user = cur.fetchone()
        if not user:
            raise HTTPException(401, "Неверные данные или недостаточно прав")
        return {"id": user["id"], "last_name": user["last_name"], "role": user["role"]}
    finally:
        cur.close()
        conn.close()


# ========== АДМИН ==========

@app.get("/api/admin/pending-users")
def get_pending_users():
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, last_name, created_at FROM users WHERE role = 'pending' ORDER BY created_at")
        rows = cur.fetchall()
        for r in rows:
            if r.get("created_at"):
                r["created_at"] = r["created_at"].isoformat()
        return rows
    finally:
        cur.close()
        conn.close()


@app.get("/api/admin/approved-users")
def get_approved_users():
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, last_name, role, created_at FROM users WHERE role != 'pending' ORDER BY last_name")
        rows = cur.fetchall()
        for r in rows:
            if r.get("created_at"):
                r["created_at"] = r["created_at"].isoformat()
        return rows
    finally:
        cur.close()
        conn.close()


@app.put("/api/admin/users/{user_id}")
def update_user(user_id: int, req: UpdateUserRequest):
    conn = get_db()
    cur = conn.cursor()
    try:
        updates = []
        values = []
        if req.last_name is not None:
            updates.append("last_name = %s")
            values.append(req.last_name)
        if req.password is not None:
            updates.append("password = %s")
            values.append(req.password)
        if req.role is not None:
            if req.role not in ("pending", "viewer", "user", "admin"):
                raise HTTPException(400, "Недопустимая роль")
            updates.append("role = %s")
            values.append(req.role)
        if not updates:
            raise HTTPException(400, "Нет данных для обновления")
        updates.append("updated_at = NOW()")
        values.append(user_id)
        cur.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = %s", values)
        conn.commit()
        return {"message": "Пользователь обновлён"}
    finally:
        cur.close()
        conn.close()


@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: int):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        return {"message": "Пользователь удалён"}
    finally:
        cur.close()
        conn.close()


# ========== СКАНИРОВАНИЕ ==========

@app.post("/api/scan")
def create_scan(req: ScanRequest):
    conn = get_db()
    cur = conn.cursor()
    try:
        scanned_at = datetime.fromisoformat(req.scanned_at)
        note = "ok"
        sound = "success"

        # Проверка: точная пара уже есть?
        cur.execute("SELECT id FROM scan_records WHERE box_id = %s AND ttn = %s", (req.box_id, req.ttn))
        if cur.fetchone():
            note = "Такая связка BoxID и ТТН уже существует"
            sound = "neutral"
        else:
            # BoxID уже привязан к другому ТТН?
            cur.execute("SELECT ttn FROM scan_records WHERE box_id = %s AND ttn != %s LIMIT 1", (req.box_id, req.ttn))
            if cur.fetchone():
                note = "такой номер BoxID уже привязан к другому номеру ТТН"
                sound = "error"
            else:
                # ТТН уже привязан к другому BoxID?
                cur.execute("SELECT box_id FROM scan_records WHERE ttn = %s AND box_id != %s LIMIT 1", (req.ttn, req.box_id))
                if cur.fetchone():
                    note = "такой номер ТТН уже привязан к другому номеру BoxID"
                    sound = "error"

        cur.execute(
            "INSERT INTO scan_records (box_id, ttn, user_last_name, scanned_at, note) VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (req.box_id, req.ttn, req.user_last_name, scanned_at, note)
        )
        record_id = cur.fetchone()["id"]
        conn.commit()
        return {"id": record_id, "note": note, "sound": sound}
    finally:
        cur.close()
        conn.close()


@app.post("/api/scan/batch")
def create_scan_batch(req: ScanBatchRequest):
    conn = get_db()
    cur = conn.cursor()
    results = []
    try:
        for r in req.records:
            scanned_at = datetime.fromisoformat(r.scanned_at)
            cur.execute(
                "INSERT INTO scan_records (box_id, ttn, user_last_name, scanned_at, note) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (r.box_id, r.ttn, r.user_last_name, scanned_at, "Зафиксировано без интернет подключения")
            )
            results.append(cur.fetchone()["id"])
        conn.commit()
        return {"synced": len(results), "ids": results}
    finally:
        cur.close()
        conn.close()


@app.get("/api/scan/history")
def get_scan_history(
    box_id: Optional[str] = None,
    ttn: Optional[str] = None,
    user_last_name: Optional[str] = None,
    note_filter: Optional[str] = None,
    hours: int = 24
):
    conn = get_db()
    cur = conn.cursor()
    try:
        conditions = ["scanned_at >= NOW() - INTERVAL '%s hours'"]
        values: list = [hours]
        if box_id:
            conditions.append("box_id ILIKE %s")
            values.append(f"%{box_id}%")
        if ttn:
            conditions.append("ttn ILIKE %s")
            values.append(f"%{ttn}%")
        if user_last_name:
            conditions.append("user_last_name ILIKE %s")
            values.append(f"%{user_last_name}%")
        if note_filter:
            conditions.append("note = %s")
            values.append(note_filter)
        where = " AND ".join(conditions)
        cur.execute(
            f"SELECT id, box_id, ttn, user_last_name, scanned_at, note FROM scan_records WHERE {where} ORDER BY scanned_at DESC LIMIT 500",
            values
        )
        rows = cur.fetchall()
        for row in rows:
            row["scanned_at"] = row["scanned_at"].isoformat()
        return rows
    finally:
        cur.close()
        conn.close()


@app.get("/api/health")
def health():
    return {"status": "ok"}
