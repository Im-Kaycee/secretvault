import sqlite3
from pathlib import Path
import time
DEFAULT_DB_PATH = Path.home() / ".secretvault" / "vault.db"


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(db_path)


def init_db(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            path TEXT PRIMARY KEY,
            ciphertext BLOB NOT NULL,
            wrapped_dek BLOB NOT NULL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            action TEXT NOT NULL,
            path TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            this_hash TEXT NOT NULL
        )
    """)
    conn.commit()
def put_secret(conn: sqlite3.Connection, path: str, ciphertext: bytes, wrapped_dek: bytes):
    now = time.time()
    conn.execute(
        """
        INSERT INTO secrets (path, ciphertext, wrapped_dek, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
            ciphertext = excluded.ciphertext,
            wrapped_dek = excluded.wrapped_dek,
            updated_at = excluded.updated_at
        """,
        (path, ciphertext, wrapped_dek, now, now),
    )
    conn.commit()
    
def get_secret(conn: sqlite3.Connection, path: str) -> tuple[bytes, bytes] | None:
    """Returns (ciphertext, wrapped_dek), or None if path doesn't exist."""
    row = conn.execute(
        "SELECT ciphertext, wrapped_dek FROM secrets WHERE path = ?", (path,)
    ).fetchone()
    return (row[0], row[1]) if row else None

def list_secrets(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute("SELECT path FROM secrets ORDER BY path").fetchall()
    return [r[0] for r in rows]
def delete_secret(conn: sqlite3.Connection, path: str) -> bool:
    cursor = conn.execute("DELETE FROM secrets WHERE path = ?", (path,))
    conn.commit()
    return cursor.rowcount > 0
#KEK rotation support - need to be able to get all wrapped DEKs and update them with new ones
def get_all_wrapped_deks(conn: sqlite3.Connection) -> list[tuple[str, bytes]]:
    """Used during key rotation - need every path's wrapped DEK to re-wrap them all."""
    rows = conn.execute("SELECT path, wrapped_dek FROM secrets").fetchall()
    return [(r[0], r[1]) for r in rows]


def update_wrapped_dek(conn: sqlite3.Connection, path: str, new_wrapped_dek: bytes):
    conn.execute(
        "UPDATE secrets SET wrapped_dek = ? WHERE path = ?", (new_wrapped_dek, path)
    )
    conn.commit()