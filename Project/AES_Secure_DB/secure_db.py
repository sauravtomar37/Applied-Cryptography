"""
secure_db.py - AES-256-GCM encrypted database layer on top of SQLite.

How it works (big picture)
--------------------------
1. A passphrase is stretched into a 256-bit master key with scrypt.
   The key is NEVER written to the database or to disk.
2. HKDF splits the master key into two separate keys:
      - an encryption key (AES-256-GCM)
      - an index key (HMAC-SHA256, used for searching on encrypted emails)
3. Every sensitive column of every row is encrypted on its own with a fresh
   random nonce. The column name and record id are tied to the ciphertext
   (AAD), so a ciphertext cannot be copied into another row or column.
4. GCM adds a 16-byte tag. If anyone changes even one bit of the stored
   data, decryption fails instead of returning wrong data.
5. All SQL uses "?" placeholders, so user input is never pasted into SQL.
6. Users log in with a password; their ROLE decides what they may do and
   whether they see real values or masked values.
7. Every sensitive action (and every denied action) goes into an audit log.
"""

import hmac
import secrets
import sqlite3
import time
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF, scrypt
from Crypto.Random import get_random_bytes

# ----------------------------------------------------------------- settings
KEY_LEN = 32      # 32 bytes = 256 bits  -> AES-256
NONCE_LEN = 12    # 96-bit nonce, the size GCM is designed for
TAG_LEN = 16      # 128-bit authentication tag

# Columns that hold sensitive data. Order matters: it matches the table.
SENSITIVE_FIELDS = ("name", "phone", "email", "national_id", "diagnosis")

ROLE_PERMISSIONS = {
    # read       = may see records, but only MASKED values (e.g. S**** S****)
    # read_plain = may see the real decrypted values
    "admin":   {"create", "read", "read_plain", "update", "delete", "manage_users"},
    "doctor":  {"create", "read", "read_plain", "update"},
    "auditor": {"read"},
}

MAX_FAILED_LOGINS = 3
LOCK_SECONDS = 60


# ---------------------------------------------------------------- exceptions
class AuthError(Exception):
    """Login failed, not logged in, or wrong database passphrase."""


class PermissionDenied(Exception):
    """User is logged in but their role does not allow this action."""


class TamperError(Exception):
    """Stored data failed its integrity check (changed, moved or corrupted)."""


# ------------------------------------------------------------- crypto engine
class CryptoEngine:
    """Does all the cryptography. Holds the keys in memory only."""

    def __init__(self, passphrase: str, salt: bytes):
        master = scrypt(passphrase.encode("utf-8"), salt, KEY_LEN, N=2**15, r=8, p=1)
        self._enc_key = HKDF(master, KEY_LEN, salt, SHA256, context=b"aes-256-gcm field encryption")
        self._idx_key = HKDF(master, KEY_LEN, salt, SHA256, context=b"hmac blind index")

    def encrypt(self, text: str, aad: bytes) -> bytes:
        """Return nonce(12) + tag(16) + ciphertext."""
        nonce = get_random_bytes(NONCE_LEN)
        cipher = AES.new(self._enc_key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(text.encode("utf-8"))
        return nonce + tag + ciphertext

    def decrypt(self, blob: bytes, aad: bytes) -> str:
        if blob is None or len(blob) < NONCE_LEN + TAG_LEN:
            raise TamperError("Stored value is too short to be valid ciphertext")
        nonce = blob[:NONCE_LEN]
        tag = blob[NONCE_LEN:NONCE_LEN + TAG_LEN]
        ciphertext = blob[NONCE_LEN + TAG_LEN:]
        cipher = AES.new(self._enc_key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
        cipher.update(aad)
        try:
            plain = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as err:
            raise TamperError("Integrity check failed: data was changed, moved or the key is wrong") from err
        return plain.decode("utf-8")

    def blind_index(self, value: str) -> str:
        """Keyed hash of a value. Lets us search for an exact email without decrypting every row."""
        normal = value.strip().lower().encode("utf-8")
        return hmac.new(self._idx_key, normal, "sha256").hexdigest()


def _hash_password(password: str, salt: bytes) -> bytes:
    return scrypt(password.encode("utf-8"), salt, 32, N=2**14, r=8, p=1)


def mask(field: str, value: str) -> str:
    """Hide most of a value. Used for roles that may not see real data."""
    if field == "name":
        return " ".join(w[0] + "*" * (len(w) - 1) for w in value.split())
    if field == "phone":
        return "*" * max(len(value) - 2, 0) + value[-2:]
    if field == "email":
        local, _, domain = value.partition("@")
        return local[:1] + "***@" + domain
    if field == "national_id":
        return "*" * max(len(value) - 4, 0) + value[-4:]
    return "[hidden]"


@dataclass(frozen=True)
class Session:
    """What login() hands back. The token is checked against the server-side list."""
    username: str
    role: str
    token: str


# ------------------------------------------------------------------ database
class SecureDB:
    INSERT_SQL = (
        "INSERT INTO patients (id, " + ", ".join(SENSITIVE_FIELDS) + ", email_idx, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )

    def __init__(self, path: str, passphrase: str, audit_reads: bool = True):
        self.path = path
        self.audit_reads = audit_reads
        self._sessions = {}                     # token -> (username, role)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        try:
            self._create_schema()
            salt = self._load_or_create_salt()
            self.crypto = CryptoEngine(passphrase, salt)
            self._verify_passphrase()
        except Exception:
            self.conn.close()
            raise

    # ------------------------------------------------------------ set-up
    def _create_schema(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY, value BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY, salt BLOB NOT NULL, pw_hash BLOB NOT NULL,
                role TEXT NOT NULL,
                failed_logins INTEGER NOT NULL DEFAULT 0,
                locked_until REAL NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS patients (
                id TEXT PRIMARY KEY,
                name BLOB NOT NULL, phone BLOB NOT NULL, email BLOB NOT NULL,
                national_id BLOB NOT NULL, diagnosis BLOB NOT NULL,
                email_idx TEXT NOT NULL,
                created_at REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_patients_email ON patients(email_idx);
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL, username TEXT, action TEXT NOT NULL,
                record_id TEXT, allowed INTEGER NOT NULL);
            """
        )

    def _load_or_create_salt(self) -> bytes:
        row = self.conn.execute("SELECT value FROM meta WHERE key = 'kdf_salt'").fetchone()
        if row:
            return row["value"]
        salt = get_random_bytes(16)             # a salt is not secret
        self.conn.execute("INSERT INTO meta (key, value) VALUES ('kdf_salt', ?)", (salt,))
        self.conn.commit()
        return salt

    def _verify_passphrase(self):
        """Store (first time) or check (later) a small encrypted value to detect a wrong passphrase."""
        aad = b"meta:key_check"
        row = self.conn.execute("SELECT value FROM meta WHERE key = 'key_check'").fetchone()
        if row is None:
            blob = self.crypto.encrypt("key-check-ok", aad)
            self.conn.execute("INSERT INTO meta (key, value) VALUES ('key_check', ?)", (blob,))
            self.conn.commit()
            return
        try:
            self.crypto.decrypt(row["value"], aad)
        except TamperError as err:
            raise AuthError("Wrong database passphrase") from err

    @staticmethod
    def _aad(column: str, record_id: str) -> bytes:
        return f"patients:{column}:{record_id}".encode("utf-8")

    def close(self):
        self.conn.close()

    # ------------------------------------------------------------- audit
    def _audit(self, username, action, record_id, allowed, commit=True):
        self.conn.execute(
            "INSERT INTO audit_log (ts, username, action, record_id, allowed) VALUES (?, ?, ?, ?, ?)",
            (time.time(), username, action, record_id, 1 if allowed else 0),
        )
        if commit:
            self.conn.commit()

    def audit_trail(self, session, limit=50):
        self._authorize(session, "manage_users")
        rows = self.conn.execute(
            "SELECT ts, username, action, record_id, allowed FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    # -------------------------------------------------- users and login
    def create_user(self, session, username, password, role):
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"Unknown role: {role}")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        is_first_user = self.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        if is_first_user:
            if role != "admin":
                raise ValueError("The first user must be an admin")
            actor = "<setup>"
        else:
            actor, _ = self._authorize(session, "manage_users")
        salt = get_random_bytes(16)
        try:
            self.conn.execute(
                "INSERT INTO users (username, salt, pw_hash, role) VALUES (?, ?, ?, ?)",
                (username, salt, _hash_password(password, salt), role),
            )
        except sqlite3.IntegrityError as err:
            raise ValueError("User already exists") from err
        self._audit(actor, "create_user", username, True)

    def login(self, username, password) -> Session:
        row = self.conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row is None:
            _hash_password(password, b"\x00" * 16)      # same work as a real login (hides which names exist)
            self._audit(str(username), "login", None, False)
            raise AuthError("Invalid username or password")
        if row["locked_until"] > time.time():
            self._audit(username, "login_locked", None, False)
            raise AuthError("Account is temporarily locked. Try again later.")
        if not hmac.compare_digest(_hash_password(password, row["salt"]), row["pw_hash"]):
            failed = row["failed_logins"] + 1
            locked_until = time.time() + LOCK_SECONDS if failed >= MAX_FAILED_LOGINS else 0
            self.conn.execute(
                "UPDATE users SET failed_logins = ?, locked_until = ? WHERE username = ?",
                (failed, locked_until, username),
            )
            self._audit(username, "login", None, False)
            raise AuthError("Invalid username or password")
        self.conn.execute(
            "UPDATE users SET failed_logins = 0, locked_until = 0 WHERE username = ?", (username,)
        )
        token = secrets.token_hex(16)
        self._sessions[token] = (username, row["role"])
        self._audit(username, "login", None, True)
        return Session(username, row["role"], token)

    def logout(self, session):
        self._sessions.pop(getattr(session, "token", None), None)

    def _authorize(self, session, permission, record_id=None):
        """Check the session is real and the role has the permission. Returns (username, role)."""
        info = self._sessions.get(getattr(session, "token", None))
        if info is None:
            self._audit("<anonymous>", permission, record_id, False)
            raise AuthError("Please log in first")
        username, role = info
        if permission not in ROLE_PERMISSIONS.get(role, set()):
            self._audit(username, permission, record_id, False)
            raise PermissionDenied(f"Role '{role}' is not allowed to {permission}")
        return username, role

    # ---------------------------------------------------------- records
    def _insert_records(self, session, records, action):
        username, _ = self._authorize(session, "create")
        now = time.time()
        rows, ids = [], []
        for data in records:
            missing = [f for f in SENSITIVE_FIELDS if not data.get(f)]
            if missing:
                raise ValueError(f"Missing fields: {', '.join(missing)}")
            record_id = secrets.token_hex(8)
            encrypted = [self.crypto.encrypt(str(data[f]), self._aad(f, record_id)) for f in SENSITIVE_FIELDS]
            rows.append((record_id, *encrypted, self.crypto.blind_index(data["email"]), now))
            ids.append(record_id)
        self.conn.executemany(self.INSERT_SQL, rows)
        self._audit(username, action, ",".join(ids) if len(ids) < 5 else f"{len(ids)} records", True, commit=False)
        self.conn.commit()
        return ids

    def add_patient(self, session, data) -> str:
        return self._insert_records(session, [data], "create")[0]

    def bulk_add(self, session, records):
        return self._insert_records(session, records, "bulk_create")

    def _row_to_dict(self, row, plain):
        out = {"id": row["id"], "created_at": row["created_at"]}
        for field in SENSITIVE_FIELDS:
            value = self.crypto.decrypt(row[field], self._aad(field, row["id"]))
            out[field] = value if plain else mask(field, value)
        return out

    def _rows_to_dicts(self, rows, username, role, action):
        plain = "read_plain" in ROLE_PERMISSIONS[role]
        try:
            return [self._row_to_dict(r, plain) for r in rows]
        except TamperError:
            self._audit(username, "tamper_detected", action, False)
            raise

    def get_patient(self, session, record_id):
        username, role = self._authorize(session, "read", record_id)
        row = self.conn.execute("SELECT * FROM patients WHERE id = ?", (record_id,)).fetchone()
        if row is None:
            return None
        result = self._rows_to_dicts([row], username, role, record_id)[0]
        if self.audit_reads:
            self._audit(username, "read", record_id, True)
        return result

    def find_by_email(self, session, email):
        username, role = self._authorize(session, "read")
        rows = self.conn.execute(
            "SELECT * FROM patients WHERE email_idx = ?", (self.crypto.blind_index(email),)
        ).fetchall()
        result = self._rows_to_dicts(rows, username, role, "find_by_email")
        if self.audit_reads:
            self._audit(username, "search_email", None, True)
        return result

    def list_patients(self, session, limit=100, offset=0):
        username, role = self._authorize(session, "read")
        rows = self.conn.execute(
            "SELECT * FROM patients ORDER BY created_at, id LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
        result = self._rows_to_dicts(rows, username, role, "list")
        if self.audit_reads:
            self._audit(username, "list", f"{len(result)} records", True)
        return result

    def update_field(self, session, record_id, field, value) -> bool:
        username, _ = self._authorize(session, "update", record_id)
        if field not in SENSITIVE_FIELDS:       # whitelist: a column name cannot be a "?" parameter
            raise ValueError(f"Cannot update field: {field!r}")
        if not value:
            raise ValueError("Value cannot be empty")
        blob = self.crypto.encrypt(str(value), self._aad(field, record_id))   # new random nonce each time
        if field == "email":
            cur = self.conn.execute(
                "UPDATE patients SET email = ?, email_idx = ? WHERE id = ?",
                (blob, self.crypto.blind_index(value), record_id),
            )
        else:
            cur = self.conn.execute(f"UPDATE patients SET {field} = ? WHERE id = ?", (blob, record_id))
        self._audit(username, f"update:{field}", record_id, True, commit=False)
        self.conn.commit()
        return cur.rowcount == 1

    def delete_patient(self, session, record_id) -> bool:
        username, _ = self._authorize(session, "delete", record_id)
        cur = self.conn.execute("DELETE FROM patients WHERE id = ?", (record_id,))
        self._audit(username, "delete", record_id, True, commit=False)
        self.conn.commit()
        return cur.rowcount == 1
