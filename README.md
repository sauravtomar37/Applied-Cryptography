# Applied-Cryptography
AES Based Secure Database

# AES Secure Database

## 1. Project Description

AES Secure Database is a Python-based secure database system that protects sensitive patient information using **AES-256-GCM encryption** and SQLite.

The system encrypts sensitive information before storing it in the database. It also provides user authentication, role-based access control, password protection, data integrity verification, and activity logging.

## 2. Features

- **AES-256-GCM Encryption:** Encrypts sensitive patient information.
- **Password-Based Key Derivation:** Uses Scrypt to derive encryption keys.
- **User Authentication:** Allows users to log in securely.
- **Role-Based Access Control:** Supports Admin, Doctor, and Auditor roles.
- **Data Masking:** Hides sensitive information from unauthorized roles.
- **Blind Indexing:** Supports searching records using encrypted email data.
- **Tamper Detection:** Detects unauthorized modifications to encrypted data.
- **Audit Logging:** Records user activities and access attempts.
- **Security Testing:** Tests encryption, authentication, access control, and data integrity.
- **Performance Benchmarking:** Compares encrypted and unencrypted database performance.

## 3. Technologies Used

- Python
- SQLite
- AES-256-GCM
- Scrypt
- HKDF
- HMAC-SHA256
- PyCryptodome
- Matplotlib

## 4. Project Requirements

Make sure the following software is installed:

- Python 3.9 or above
- pip (Python package manager)

## 5. How to Run the Project

### Step 1: Extract the Project

Extract the `AES_Secure_DB.zip` file.

Open the extracted project folder:

```bash
cd AES_Secure_DB
```

### Step 2: Create a Virtual Environment

Create a Python virtual environment:

```bash
python -m venv venv
```

### Step 3: Activate the Virtual Environment

**Windows:**

```bash
venv\Scripts\activate
```

**Linux / macOS:**

```bash
source venv/bin/activate
```

### Step 4: Install Dependencies

Install the required Python libraries:

```bash
pip install -r requirements.txt
```

### Step 5: Run the Main Demonstration

Execute the following command:

```bash
python demo.py
```

The demonstration automatically performs the following operations:

1. Creates a secure SQLite database.
2. Creates Admin, Doctor, and Auditor accounts.
3. Adds sample patient records.
4. Encrypts patient information using AES-256-GCM.
5. Displays the encrypted data stored in the database.
6. Demonstrates authorized data retrieval.
7. Demonstrates masked data access for the Auditor.
8. Demonstrates searching using encrypted email data.
9. Tests unauthorized access and incorrect passwords.
10. Demonstrates updating patient information.
11. Displays the audit log.

**Note:** The demonstration recreates `demo_patients.db` every time it runs. Any previous data in that demo database will be deleted.

## 6. Running Security Tests

To verify the security features of the project, execute:

```bash
python security_tests.py
```

The test program checks:

- Plaintext data leakage.
- User authentication.
- Role-based access permissions.
- SQL injection protection.
- Data tampering detection.
- Encryption integrity.
- Random nonce generation.
- Incorrect database passphrase handling.

The output displays PASS or FAIL for each security test.

## 7. Running Performance Benchmarks

To compare the performance of encrypted and unencrypted databases, execute:

```bash
python benchmark.py
```

By default, the benchmark tests databases containing:

- 100 records
- 1,000 records
- 10,000 records

To specify custom record counts:

```bash
python benchmark.py 100 500 1000
```

The benchmark evaluates encryption speed, decryption speed, database operations, searching, record retrieval, and database storage size.

After execution, the following output files are generated:

- `benchmark_results.csv` – Contains benchmark results.
- `benchmark_charts.png` – Contains performance comparison charts.

## 8. Project Files

| File | Description |
|---|---|
| `secure_db.py` | Main encryption and secure database implementation. |
| `demo.py` | Demonstrates the working of the secure database. |
| `security_tests.py` | Performs security verification tests. |
| `benchmark.py` | Measures and compares database performance. |
| `requirements.txt` | Contains the required Python libraries. |
| `demo_patients.db` | SQLite database used by the demonstration. |
| `benchmark_results.csv` | Stores benchmark results. |
| `benchmark_charts.png` | Displays benchmark graphs. |

## 9. User Roles

| Role | Permissions |
|---|---|
| Admin | Create, read, update, delete records, manage users, and view audit logs. |
| Doctor | Create, read, and update patient records. |
| Auditor | Read patient records with sensitive information masked. |

## 10. Important Security Information

- The database encryption passphrase must be remembered.
- The encryption keys are derived using Scrypt and are kept in memory rather than stored in the database.
- Sensitive patient information is encrypted before database storage.
- Each encrypted field uses a fresh random nonce.
- AES-GCM authentication detects unauthorized changes to encrypted data.
- Passwords are stored as salted Scrypt hashes.
- Never use the demonstration passwords or sample patient information in a real deployment.

## 11. Quick Start

For a quick execution, use these commands:

```bash
cd AES_Secure_DB

python -m venv venv

# Windows
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the project
python demo.py

# Run security tests
python security_tests.py

# Run performance benchmarks
python benchmark.py
```

---

**Project:** AES Secure Database

**Purpose:** Secure storage and management of sensitive database information using AES-256-GCM encryption.
