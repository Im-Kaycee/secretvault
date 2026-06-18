import hashlib
import time


def compute_hash(prev_hash: str, timestamp: float, action: str, path: str) -> str:
    content = f"{prev_hash}|{timestamp}|{action}|{path}"
    return hashlib.sha256(content.encode()).hexdigest()

GENESIS_HASH = "GENESIS"


def get_last_hash(conn) -> str:
    row = conn.execute(
        "SELECT this_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else GENESIS_HASH


def log_action(conn, action: str, path: str):
    prev_hash = get_last_hash(conn)
    timestamp = time.time()
    this_hash = compute_hash(prev_hash, timestamp, action, path)

    conn.execute(
        """
        INSERT INTO audit_log (timestamp, action, path, prev_hash, this_hash)
        VALUES (?, ?, ?, ?, ?)
        """,
        (timestamp, action, path, prev_hash, this_hash),
    )
    conn.commit()
def get_log_entries(conn) -> list[tuple]:
    return conn.execute(
        "SELECT id, timestamp, action, path, prev_hash, this_hash FROM audit_log ORDER BY id ASC"
    ).fetchall()
    
def verify_chain(conn) -> tuple[bool, str | None]:
    rows = get_log_entries(conn)

    expected_prev = GENESIS_HASH
    for row in rows:
        entry_id, timestamp, action, path, stored_prev_hash, stored_this_hash = row

        if stored_prev_hash != expected_prev:
            return False, f"Entry {entry_id}: prev_hash doesn't match the actual previous entry's hash (chain link broken)"

        recomputed = compute_hash(stored_prev_hash, timestamp, action, path)
        if recomputed != stored_this_hash:
            return False, f"Entry {entry_id}: stored hash doesn't match recomputed hash (content was altered)"

        expected_prev = stored_this_hash

    return True, None