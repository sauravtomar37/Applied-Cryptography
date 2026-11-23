"""
demo.py - a short walk through of the Secure Database.

Run:  python demo.py
(The passphrase can be set with the SECURE_DB_PASSPHRASE environment variable.)
"""
import os
import sqlite3
import time

from secure_db import AuthError, PermissionDenied, SecureDB

DB_FILE = "demo_patients.db"
PASSPHRASE = os.environ.get("SECURE_DB_PASSPHRASE", "demo-passphrase-change-me")


def step(text):
    print(f"\n=== {text} ===")


if os.path.exists(DB_FILE):
    os.remove(DB_FILE)

step("1. Open the database (this derives the AES-256 key from the passphrase)")
db = SecureDB(DB_FILE, PASSPHRASE)
db.create_user(None, "alice_admin", "Admin#Pass123", "admin")          # first user must be admin
admin = db.login("alice_admin", "Admin#Pass123")
db.create_user(admin, "dr_rao", "Doctor#Pass123", "doctor")
db.create_user(admin, "audit_amit", "Audit#Pass123", "auditor")
print("Users created: alice_admin (admin), dr_rao (doctor), audit_amit (auditor)")

step("2. Doctor adds two patient records (encrypted before they touch the database)")
doctor = db.login("dr_rao", "Doctor#Pass123")
id1 = db.add_patient(doctor, {
    "name": "Saurav Kumar", "phone": "+919876543210", "email": "saurav.kumar@example.com",
    "national_id": "123456789012", "diagnosis": "Type 2 diabetes",
})
id2 = db.add_patient(doctor, {
    "name": "Priya Sharma", "phone": "+919123456780", "email": "priya.sharma@example.com",
    "national_id": "998877665544", "diagnosis": "Asthma",
})
print("Saved records:", id1, id2)

step("3. What an attacker who steals the .db file sees")
raw = sqlite3.connect(DB_FILE)
row = raw.execute("SELECT id, name, phone, diagnosis FROM patients WHERE id = ?", (id1,)).fetchone()
raw.close()
print("id        :", row[0])
print("name      :", row[1][:20].hex(), "...  (", len(row[1]), "bytes )")
print("phone     :", row[2][:20].hex(), "...")
print("diagnosis :", row[3][:20].hex(), "...")

step("4. Doctor reads the record (authorized -> real values)")
print(db.get_patient(doctor, id1))

step("5. Auditor reads the same record (not allowed to see real values -> masked)")
auditor = db.login("audit_amit", "Audit#Pass123")
print(db.get_patient(auditor, id1))

step("6. Search by email (works on the encrypted data through a blind index)")
print([r["name"] for r in db.find_by_email(doctor, "Priya.Sharma@example.com")])

step("7. Things that must fail")
try:
    db.delete_patient(auditor, id1)
except PermissionDenied as err:
    print("Auditor delete  ->", err)
try:
    db.login("dr_rao", "wrong-password")
except AuthError as err:
    print("Wrong password ->", err)
try:
    SecureDB(DB_FILE, "wrong passphrase")
except AuthError as err:
    print("Wrong passphrase ->", err)

step("8. Update one field (a new random nonce is used, so the ciphertext changes)")
db.update_field(doctor, id1, "diagnosis", "Type 2 diabetes - under control")
print(db.get_patient(doctor, id1)["diagnosis"])

step("9. Audit log (admin only)")
for entry in reversed(db.audit_trail(admin, limit=8)):
    when = time.strftime("%H:%M:%S", time.localtime(entry["ts"]))
    status = "ALLOWED" if entry["allowed"] else "DENIED "
    print(f"{when}  {status}  {entry['username']:<12} {entry['action']:<18} {entry['record_id'] or ''}")

db.close()
print("\nDone. Database file:", DB_FILE)
