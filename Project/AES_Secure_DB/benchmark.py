
import csv
import os
import random
import sqlite3
import statistics
import sys
import tempfile
import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from secure_db import SENSITIVE_FIELDS, SecureDB

random.seed(42)
SIZES = [int(a) for a in sys.argv[1:]] or [100, 1000, 10000]

FIRST = ["Aarav", "Priya", "Rahul", "Sneha", "Vikram", "Anita", "Rohan", "Kavya", "Arjun", "Meera", "Saurav", "Neha"]
LAST = ["Sharma", "Verma", "Singh", "Kumar", "Gupta", "Patel", "Rao", "Mishra", "Yadav", "Jha", "Das", "Nair"]
DIAGNOSES = ["Type 2 diabetes", "Asthma", "Hypertension", "Migraine", "Anemia", "Thyroid disorder", "Arthritis"]


def fake_record(i):
    first, last = random.choice(FIRST), random.choice(LAST)
    return {
        "name": f"{first} {last}",
        "phone": f"+91{random.randint(7000000000, 9999999999)}",
        "email": f"{first.lower()}.{last.lower()}{i}@example.com",
        "national_id": str(random.randint(10**11, 10**12 - 1)),
        "diagnosis": random.choice(DIAGNOSES),
    }


def timed(fn):
    start = time.perf_counter()
    out = fn()
    return time.perf_counter() - start, out


# ------------------------------------------------ 1. raw AES speed (no database)
def raw_aes_benchmark(n=20000):
    sample = b"Saurav Kumar, +919876543210"              # a typical short field
    key128, key256 = get_random_bytes(16), get_random_bytes(32)

    def gcm(key):
        def enc():
            c = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
            ct, tag = c.encrypt_and_digest(sample)
            return c.nonce, ct, tag

        def dec(parts):
            nonce, ct, tag = parts
            AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
        return enc, dec

    def cbc(key):
        def enc():
            c = AES.new(key, AES.MODE_CBC, iv=get_random_bytes(16))
            return c.iv, c.encrypt(pad(sample, 16))

        def dec(parts):
            iv, ct = parts
            unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct), 16)
        return enc, dec

    rows = []
    for label, (enc, dec) in [("AES-128-GCM", gcm(key128)), ("AES-256-GCM", gcm(key256)), ("AES-256-CBC", cbc(key256))]:
        t_enc, sealed = timed(lambda: [enc() for _ in range(n)])
        t_dec, _ = timed(lambda: [dec(s) for s in sealed])
        rows.append({"cipher": label, "encrypt_us": t_enc / n * 1e6, "decrypt_us": t_dec / n * 1e6})
    return rows


# -------------------------------------------------------- 2-5. database tests
def make_plain_db(path, records, ids):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE patients (id TEXT PRIMARY KEY, name TEXT, phone TEXT, email TEXT, "
                 "national_id TEXT, diagnosis TEXT, created_at REAL)")
    conn.execute("CREATE INDEX idx_email ON patients(5email)")
    now = time.time()
    rows = [(rid, *[r[f] for f in SENSITIVE_FIELDS], now) for rid, r in zip(ids, records)]
    t, _ = timed(lambda: (conn.executemany("INSERT INTO patients VALUES (?,?,?,?,?,?,?)", rows), conn.commit()))
    return conn, t


def run_size(n, workdir):
    records = [fake_record(i) for i in range(n)]
    out = {"records": n}

    # ---- encrypted database (audit_reads off so we measure crypto + query, not log writes)
    secure_path = os.path.join(workdir, f"secure_{n}.db")
    db = SecureDB(secure_path, "benchmark-passphrase", audit_reads=False)
    db.create_user(None, "bench_admin", "Bench#Pass123", "admin")
    session = db.login("bench_admin", "Bench#Pass123")
    t_enc_insert, ids = timed(lambda: db.bulk_add(session, records))

    # ---- plaintext database with exactly the same data and ids
    plain_path = os.path.join(workdir, f"plain_{n}.db")
    plain, t_plain_insert = make_plain_db(plain_path, records, ids)

    out["insert_plain_ms_per_rec"] = t_plain_insert / n * 1e3
    out["insert_secure_ms_per_rec"] = t_enc_insert / n * 1e3

    # ---- point lookup by id
    k = min(500, n)
    sample_ids = random.sample(ids, k)
    t_plain, _ = timed(lambda: [plain.execute("SELECT * FROM patients WHERE id = ?", (i,)).fetchone() for i in sample_ids])
    t_secure, _ = timed(lambda: [db.get_patient(session, i) for i in sample_ids])
    out["lookup_plain_ms"] = t_plain / k * 1e3
    out["lookup_secure_ms"] = t_secure / k * 1e3

    db.audit_reads = True                                    # same lookups, with an audit-log write per read
    k2 = min(100, n)
    t_audit, _ = timed(lambda: [db.get_patient(session, i) for i in sample_ids[:k2]])
    db.audit_reads = False
    out["lookup_secure_with_audit_ms"] = t_audit / k2 * 1e3

    # ---- search by email
    emails = [r["email"] for r in random.sample(records, k)]
    t_plain, _ = timed(lambda: [plain.execute("SELECT * FROM patients WHERE email = ?", (e,)).fetchall() for e in emails])
    t_blind, _ = timed(lambda: [db.find_by_email(session, e) for e in emails])
    out["search_plain_ms"] = t_plain / k * 1e3
    out["search_blind_index_ms"] = t_blind / k * 1e3

    # the naive alternative: decrypt every email and compare (what you must do WITHOUT a blind index)
    k3 = min(10, n)

    def scan_search(target):
        rows = db.conn.execute("SELECT id, email FROM patients").fetchall()
        return [r["id"] for r in rows if db.crypto.decrypt(r["email"], db._aad("email", r["id"])) == target]
    t_scan, _ = timed(lambda: [scan_search(e) for e in emails[:k3]])
    out["search_decrypt_scan_ms"] = t_scan / k3 * 1e3

    # ---- retrieve everything
    t_plain, _ = timed(lambda: plain.execute("SELECT * FROM patients").fetchall())
    t_secure, rows = timed(lambda: db.list_patients(session, limit=n))
    assert len(rows) == n
    out["retrieve_all_plain_ms"] = t_plain * 1e3
    out["retrieve_all_secure_ms"] = t_secure * 1e3

    # ---- storage
    plain.close()
    db.close()
    out["size_plain_kb"] = os.path.getsize(plain_path) / 1024
    out["size_secure_kb"] = os.path.getsize(secure_path) / 1024
    out["size_overhead_pct"] = (out["size_secure_kb"] / out["size_plain_kb"] - 1) * 100
    return out


def print_report(aes_rows, results):
    print("\n1. RAW AES SPEED (one short field, microseconds per operation)")
    for r in aes_rows:
        print(f"   {r['cipher']:<12} encrypt {r['encrypt_us']:7.1f} us    decrypt {r['decrypt_us']:7.1f} us")

    def line(title, key_plain, key_secure, unit="ms", extra=None):
        print(f"\n{title}")
        for r in results:
            slow = r[key_secure] / r[key_plain] if r[key_plain] else float("nan")
            text = f"   {r['records']:>6} records   plain {r[key_plain]:9.4f} {unit}   encrypted {r[key_secure]:9.4f} {unit}   ({slow:5.1f}x)"
            print(text)

    line("2. ENCRYPTION TIME - insert cost per record", "insert_plain_ms_per_rec", "insert_secure_ms_per_rec")
    line("3a. QUERY TIME - lookup by id (per query)", "lookup_plain_ms", "lookup_secure_ms")
    line("3b. QUERY TIME - search by email, using the blind index (per query)", "search_plain_ms", "search_blind_index_ms")
    print("\n3c. Search by email WITHOUT a blind index (decrypt every row), per query")
    for r in results:
        print(f"   {r['records']:>6} records   {r['search_decrypt_scan_ms']:9.2f} ms   "
              f"(blind index is {r['search_decrypt_scan_ms'] / r['search_blind_index_ms']:,.0f}x faster)")
    print("\n3d. Lookup by id with the audit log switched on (extra disk write per read)")
    for r in results:
        print(f"   {r['records']:>6} records   {r['lookup_secure_with_audit_ms']:9.3f} ms per lookup")
    line("4. RETRIEVAL - read and decrypt the whole table (total time)", "retrieve_all_plain_ms", "retrieve_all_secure_ms")
    line("5. STORAGE - database file size", "size_plain_kb", "size_secure_kb", unit="KB")
    for r in results:
        print(f"   {r['records']:>6} records   overhead {r['size_overhead_pct']:+.1f}%")


def save_csv(results, path="benchmark_results.csv"):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print(f"\nSaved {path}")


def save_charts(aes_rows, results, path="benchmark_charts.png"):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed - skipping charts")
        return
    import numpy as np
    labels = [str(r["records"]) for r in results]
    x = np.arange(len(labels))
    w = 0.38
    fig, axes = plt.subplots(2, 2, figsize=(11, 8))

    ax = axes[0][0]
    ax.bar([r["cipher"] for r in aes_rows], [r["encrypt_us"] for r in aes_rows], w, label="encrypt")
    ax.bar([r["cipher"] for r in aes_rows], [r["decrypt_us"] for r in aes_rows], w, bottom=[r["encrypt_us"] for r in aes_rows], label="decrypt")
    ax.set_title("Raw AES speed (per field)")
    ax.set_ylabel("microseconds")
    ax.legend()

    ax = axes[0][1]
    ax.bar(x - w / 2, [r["lookup_plain_ms"] for r in results], w, label="plaintext")
    ax.bar(x + w / 2, [r["lookup_secure_ms"] for r in results], w, label="AES-256-GCM")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_title("Lookup by id (per query)")
    ax.set_xlabel("records in table")
    ax.set_ylabel("ms")
    ax.legend()

    ax = axes[1][0]
    ax.bar(x - w / 2, [r["retrieve_all_plain_ms"] for r in results], w, label="plaintext")
    ax.bar(x + w / 2, [r["retrieve_all_secure_ms"] for r in results], w, label="AES-256-GCM")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_yscale("log")
    ax.set_title("Read + decrypt the whole table")
    ax.set_xlabel("records in table")
    ax.set_ylabel("ms (log scale)")
    ax.legend()

    ax = axes[1][1]
    ax.bar(x - w / 2, [r["size_plain_kb"] for r in results], w, label="plaintext")
    ax.bar(x + w / 2, [r["size_secure_kb"] for r in results], w, label="AES-256-GCM")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_title("Database file size")
    ax.set_xlabel("records in table")
    ax.set_ylabel("KB")
    ax.legend()

    fig.tight_layout()
    fig.savefig(path, dpi=140)
    print(f"Saved {path}")


if __name__ == "__main__":
    print(f"Benchmarking with sizes: {SIZES}  (this takes a short while)")
    aes_rows = raw_aes_benchmark()
    with tempfile.TemporaryDirectory() as workdir:
        results = [run_size(n, workdir) for n in SIZES]
    print_report(aes_rows, results)
    save_csv(results)
    save_charts(aes_rows, results)
