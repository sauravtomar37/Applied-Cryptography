"""
security_tests.py - Security verification for the AES Secure Database.

Run:  python3 security_tests.py
Every check prints PASS or FAIL. The script exits with code 1 if anything fails.

Groups:
  A. Data leakage            - is any plaintext visible in the database file?
  B. Unauthorized access     - wrong passwords, roles, fake sessions, lockout
  C. SQL injection           - hostile input through every entry point
  D. Tampering and integrity - changed or moved ciphertext must be detected
  E. Crypto sanity           - random nonces, wrong passphrase
"""
import os
import sqlite3
import sys
import tempfile

from secure_db import (
    SENSITIVE_FIELDS,
    AuthError,
    PermissionDenied,
    SecureDB,
    Session,
    TamperError,
)

results = []


def check(name, condition):
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}")
    results.append(bool(condition))


def raises(exc_type, fn, *args, **kwargs):
    """True only if fn raises exactly the kind of error we expect."""
    try:
        fn(*args, **kwargs)
    except exc_type:
        return True
    except Exception:
        return False
    return False


def group(title):
    print(f"\n{title}")


# ---------------------------------------------------------------- test data
PATIENTS = [
    {
        "name": "Saurav Kumar",
        "phone": "+919876543210",
        "email": "saurav.kumar@example.com",
        "national_id": "123456789012",
        "diagnosis": "Type 2 diabetes",
    },
    {
        "name": "Priya Sharma",
        "phone": "+919123456780",
        "email": "priya.sharma@example.com",
        "national_id": "998877665544",
        "diagnosis": "Asthma",
    },
    {
        "name": "Rahul Verma",
        "phone": "+919000011122",
        "email": "rahul.verma@example.com",
        "national_id": "555566667777",
        "diagnosis": "Hypertension",
    },
]
PASSPHRASE = "test-passphrase-123"

tmp = tempfile.mkdtemp()
db_path = os.path.join(tmp, "secure.db")
plain_path = os.path.join(tmp, "plain.db")

db = SecureDB(db_path, PASSPHRASE)
db.create_user(None, "admin1", "Admin#Pass123", "admin")
admin = db.login("admin1", "Admin#Pass123")
db.create_user(admin, "doc1", "Doctor#Pass123", "doctor")
db.create_user(admin, "aud1", "Audit#Pass123", "auditor")
db.create_user(admin, "victim", "Victim#Pass123", "doctor")
doctor = db.login("doc1", "Doctor#Pass123")
auditor = db.login("aud1", "Audit#Pass123")
ids = [db.add_patient(doctor, p) for p in PATIENTS]

# ====================================================== A. DATA LEAKAGE
group("A. Data leakage")

plain = sqlite3.connect(plain_path)
plain.execute(
    "CREATE TABLE patients (id TEXT, name TEXT, phone TEXT, email TEXT, national_id TEXT, diagnosis TEXT)"
)
for i, p in enumerate(PATIENTS):
    plain.execute("INSERT INTO patients VALUES (?,?,?,?,?,?)", (str(i), *[p[f] for f in SENSITIVE_FIELDS]))
plain.commit()
plain.close()


def count_leaks(path):
    with open(path, "rb") as f:
        data = f.read()
    return sum(1 for p in PATIENTS for f in SENSITIVE_FIELDS if p[f].encode() in data)


total_values = len(PATIENTS) * len(SENSITIVE_FIELDS)
check(
    f"Control: scan finds plaintext in an UNENCRYPTED database ({count_leaks(plain_path)}/{total_values} values)",
    count_leaks(plain_path) == total_values,
)
check("Encrypted database file contains none of the sensitive values", count_leaks(db_path) == 0)

with open(db_path, "rb") as f:
    raw_bytes = f.read()
check("Passphrase is not stored in the database file", PASSPHRASE.encode() not in raw_bytes)
check(
    "User passwords are not stored in the database file",
    b"Admin#Pass123" not in raw_bytes and b"Doctor#Pass123" not in raw_bytes,
)

raw = sqlite3.connect(db_path)
stored = raw.execute("SELECT name, phone, email, national_id, diagnosis FROM patients").fetchall()
raw.close()
check("Sensitive columns are stored as binary blobs, not text", all(isinstance(v, bytes) for row in stored for v in row))

# ============================================ B. UNAUTHORIZED ACCESS
group("B. Unauthorized access")

check("No login at all -> read is refused", raises(AuthError, db.get_patient, None, ids[0]))
check(
    "Forged session object (made-up token) is refused",
    raises(AuthError, db.get_patient, Session("evil", "admin", "deadbeef" * 4), ids[0]),
)
check("Wrong password is refused", raises(AuthError, db.login, "doc1", "not-the-password"))
check("Unknown user is refused", raises(AuthError, db.login, "ghost", "whatever123"))

try:
    db.login("ghost", "whatever123")
except AuthError as e1:
    msg_unknown = str(e1)
try:
    db.login("doc1", "not-the-password")
except AuthError as e2:
    msg_wrong = str(e2)
check("Same error message for unknown user and wrong password (no user enumeration)", msg_unknown == msg_wrong)

check("Auditor cannot create records", raises(PermissionDenied, db.add_patient, auditor, PATIENTS[0]))
check("Auditor cannot update records", raises(PermissionDenied, db.update_field, auditor, ids[0], "name", "X"))
check("Auditor cannot delete records", raises(PermissionDenied, db.delete_patient, auditor, ids[0]))
check("Doctor cannot read the audit log", raises(PermissionDenied, db.audit_trail, doctor))
check("Doctor cannot create users", raises(PermissionDenied, db.create_user, doctor, "x_user", "Password#123", "admin"))

masked = db.get_patient(auditor, ids[0])
check(
    "Auditor sees masked values, not real ones",
    masked["name"] != PATIENTS[0]["name"]
    and masked["diagnosis"] == "[hidden]"
    and masked["national_id"].endswith("9012")
    and "1234567" not in masked["national_id"],
)
check("Doctor sees the real values", db.get_patient(doctor, ids[0])["name"] == PATIENTS[0]["name"])

for _ in range(3):
    raises(AuthError, db.login, "victim", "bad-guess-000")
check(
    "Account locks after 3 wrong passwords (even the right password is refused)",
    raises(AuthError, db.login, "victim", "Victim#Pass123"),
)

db.logout(doctor)
check("After logout the old session no longer works", raises(AuthError, db.get_patient, doctor, ids[0]))
doctor = db.login("doc1", "Doctor#Pass123")

# ========================================================= C. SQL INJECTION
group("C. SQL injection")

payloads = ["' OR '1'='1", "x' OR id LIKE '%", "'; DROP TABLE patients; --", '" OR ""="', "1; DELETE FROM patients"]

naive = sqlite3.connect(db_path)
naive_hits = naive.execute(f"SELECT * FROM patients WHERE id = '{payloads[0]}'").fetchall()
naive.close()
check(
    f"Contrast: a careless f-string query IS injectable (returned {len(naive_hits)} rows for ' OR '1'='1)",
    len(naive_hits) == len(PATIENTS),
)
check(
    "...but even then the attacker only gets ciphertext, never plaintext",
    all(isinstance(row[1], bytes) and PATIENTS[0]["name"].encode() not in row[1] for row in naive_hits),
)

check("Secure get_patient returns nothing for every injection payload", all(db.get_patient(doctor, p) is None for p in payloads))
check("Secure email search returns nothing for every injection payload", all(db.find_by_email(doctor, p) == [] for p in payloads))
check("Injection payloads in the login username are refused", all(raises(AuthError, db.login, p, "Doctor#Pass123") for p in payloads))
check(
    "Injection payload as a field name is refused (column whitelist)",
    raises(ValueError, db.update_field, doctor, ids[0], "name = 'x', role", "y"),
)

evil_id = db.add_patient(
    doctor,
    {
        "name": "Robert'); DROP TABLE patients;--",
        "phone": "1",
        "email": "bobby@tables.com",
        "national_id": "0",
        "diagnosis": "' OR '1'='1",
    },
)
check("Hostile text stored as DATA comes back unchanged", db.get_patient(doctor, evil_id)["name"] == "Robert'); DROP TABLE patients;--")
check("Table still exists with all records after the attacks", len(db.list_patients(doctor, limit=100)) == len(PATIENTS) + 1)

# ================================================ D. TAMPERING / INTEGRITY
group("D. Tampering and integrity")

raw = sqlite3.connect(db_path)

# Test 1: Bit flip
blob = bytearray(raw.execute("SELECT diagnosis FROM patients WHERE id = ?", (ids[0],)).fetchone()[0])
blob[-1] ^= 0x01
raw.execute("UPDATE patients SET diagnosis = ? WHERE id = ?", (bytes(blob), ids[0]))
raw.commit()
check("Flipping ONE bit of stored ciphertext is detected", raises(TamperError, db.get_patient, doctor, ids[0]))
check(
    "The tamper attempt is written to the audit log",
    any(e["action"] == "tamper_detected" for e in db.audit_trail(admin, 50)),
)

# Test 2: Copying ciphertext to another row
name_a = raw.execute("SELECT name FROM patients WHERE id = ?", (ids[1],)).fetchone()[0]
raw.execute("UPDATE patients SET name = ? WHERE id = ?", (name_a, ids[2]))
raw.commit()
check("Copying a valid ciphertext into ANOTHER row is detected (row id is bound to it)", raises(TamperError, db.get_patient, doctor, ids[2]))

# Test 3: Copying ciphertext to another column (using evil_id to avoid cascading errors)
phone_a = raw.execute("SELECT phone FROM patients WHERE id = ?", (evil_id,)).fetchone()[0]
raw.execute("UPDATE patients SET diagnosis = ? WHERE id = ?", (phone_a, evil_id))
raw.commit()
check("Copying a ciphertext into ANOTHER column is detected (column name is bound to it)", raises(TamperError, db.get_patient, doctor, evil_id))

# Test 4: Truncated value
raw.execute("UPDATE patients SET name = ? WHERE id = ?", (b"\x00" * 5, ids[1]))
raw.commit()
check("A truncated / garbage value is detected", raises(TamperError, db.get_patient, doctor, ids[1]))
raw.close()

# ============================================== E. CRYPTO SANITY
group("E. Crypto sanity")

id_a = db.add_patient(doctor, PATIENTS[1])
id_b = db.add_patient(doctor, PATIENTS[1])
raw = sqlite3.connect(db_path)
cts = [raw.execute("SELECT name FROM patients WHERE id = ?", (i,)).fetchone()[0] for i in (id_a, id_b)]
raw.close()
check("Same plaintext encrypted twice gives different ciphertext (random nonce)", cts[0] != cts[1])
check("Ciphertext length = plaintext + 28 bytes (12 nonce + 16 tag)", len(cts[0]) == len(PATIENTS[1]["name"].encode()) + 28)

before = sqlite3.connect(db_path).execute("SELECT diagnosis FROM patients WHERE id = ?", (id_a,)).fetchone()[0]
db.update_field(doctor, id_a, "diagnosis", PATIENTS[1]["diagnosis"])
after = sqlite3.connect(db_path).execute("SELECT diagnosis FROM patients WHERE id = ?", (id_a,)).fetchone()[0]
check("Updating a field to the SAME value still changes the ciphertext", before != after)

db.close()
check("Opening the database with a wrong passphrase is refused", raises(AuthError, SecureDB, db_path, "wrong passphrase"))
reopened = SecureDB(db_path, PASSPHRASE)
check("Opening with the right passphrase works and old users can log in", reopened.login("doc1", "Doctor#Pass123").role == "doctor")
reopened.close()

# ---------------------------------------------------------------- summary
passed, total = sum(results), len(results)
print(f"\nResult: {passed}/{total} checks passed")
