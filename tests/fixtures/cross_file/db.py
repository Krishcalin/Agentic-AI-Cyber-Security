"""Database layer — sinks live here."""
import sqlite3


def run_query(search_term):
    """Executes raw SQL with input — SINK."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE name = '{search_term}'")
    return cursor.fetchall()


def run_safe_query(search_term):
    """Uses parameterized query — SAFE SINK."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE name = ?", (search_term,))
    return cursor.fetchall()
