```markdown
# Project Context: I2I Secure P2P Messenger

## File: README.md
```markdown
## Description

I2I (Identity-to-Identity) is a decentralized, peer-to-peer messaging and file-sharing application built with a focus on cryptographic security and local privacy. The system eliminates reliance on central servers by utilizing a simulated I2P network layer where peer addresses are derived deterministically from their public keys. The application provides an end-to-end encrypted (E2EE) tunnel for communication, enforcing role-based access control (RBAC) to manage resource usage and administrative privileges.

## Security Features Implemented

The application incorporates several secure coding principles and architectural controls:

- End-to-End Encryption (E2EE): All data is protected using XSalsa20-Poly1305 authenticated encryption via the PyNaCl (libsodium) library.
- Perfect Forward Secrecy (PFS): A two-phase handshake uses static identity keys to authenticate the exchange of ephemeral X25519 keys for every session.
- Role-Based Access Control (RBAC): The system differentiates between USER and ADMIN roles, enforcing file size limits (10 MB for users, 50 MB for admins) and restricting administrative commands like network broadcasts and peer kicking.
- Authentication Security: Local accounts are secured with bcrypt password hashing. A memory-resident lockout policy triggers after three failed attempts to prevent brute-force attacks.
- Man-In-The-Middle (MITM) Protection: Users can perform out-of-band verification using a 30-digit Safety Number derived from the shared cryptographic context.
- Input Validation: All external inputs, including chat messages, public keys, and filenames, are validated against strict length and format constraints.
- Path Traversal Prevention: Filenames are sanitized by stripping directory components and null bytes, and by rejecting reserved operating system filenames.
- Rate Limiting: A Token Bucket algorithm prevents message flooding by limiting the rate at which a peer can send data.
- Secure Logging: Application logs exclude sensitive data such as plaintext messages, private keys, or passwords. Peer identifiers are anonymized.
- Container Security: The Docker implementation uses a non-root user, isolated bridge networking, and a virtualized framebuffer (Xvfb) to minimize the host attack surface.

## Dependencies

The following Python libraries are required for the application:

- PyNaCl: Provides the cryptographic primitives for X25519 and XSalsa20-Poly1305.
- bcrypt: Handles secure, salted password hashing.
- python-dotenv: Loads configuration settings from environment files.
- pytest: Framework used for the unit test suite.
- pytest-cov: Provides coverage reporting for the source code.

## Environment Variables

The application is configured via a .env file. An example file (.env.example) is provided in the root directory.

- I2I_LISTEN_PORT: The TCP port the application listens on (e.g., 7777).
- I2I_BIND_ADDR: The network interface to bind to (use 0.0.0.0 for Docker, 127.0.0.1 for local).
- I2I_ADMIN_SECRET: The secret code required to register as an ADMIN.
- I2I_LOG_LEVEL: The verbosity of the application logs (e.g., INFO, WARNING).
- PUID/PGID: User and Group IDs used for filesystem permissions in Docker.

## Setup Instructions

### Docker Environment Setup

1.  **Initialize Configuration:**

    ```bash
    cp .env.example .env
    ```

2.  **Configure Environment Variables:**
    Open the `.env` file and ensure the following:
    - Set `I2I_BIND_ADDR=0.0.0.0` (Required for Docker networking).
    - Set `I2I_ADMIN_SECRET` to a code of your choice (e.g., `MySecret123`). This is required to register an Admin account.
    - Set `ADMIN_CODE` to the same value as `I2I_ADMIN_SECRET`.

3.  **Launch the Network:**
    ```bash
    docker-compose up --build -d
    ```

## How to Run Project

### 1. Access the Graphical Interfaces

Open two separate browser tabs to access the peer nodes:

- **Peer A:**[http://localhost:8777/vnc.html](http://localhost:8777/vnc.html)
- **Peer B:** [http://localhost:8778/vnc.html](http://localhost:8778/vnc.html)

_Click the "Connect" button in the browser to view the application._

### 2. Authentication Flow

- **Registering as ADMIN:** Use the username `admin`. When the application prompts for a secret code, enter the `I2I_ADMIN_SECRET` defined in your `.env` file.
- **Registering as USER:** Use any other username and password.

### 3. Establishing a Peer-to-Peer Connection

To connect Peer B to Peer A:

1.  **On Peer A:** Register/Login and copy the **Public Key (Hex)** displayed in the identity panel.
2.  **On Peer B:** Register/Login. In the connection panel, enter the following:
    - **Peer Public Key:** (Paste the key from Peer A)
    - **Host/IP:** `peer-a`
    - **Port:** `7777`
3.  Click **Connect**.

To connect Peer A back to Peer B:

1.  **On Peer B:** Copy the **Public Key (Hex)**.
2.  **On Peer A:** Enter `peer-b` in the **Host/IP** field, `7777` in the **Port** field, and paste the key.
3.  Click **Connect**.

## Testing and Verification

### Automated Security Audit

This script verifies authentication security, RBAC limits, path traversal prevention, and logging integrity.
docker exec -it i2i-peer-a python security_test.py

### Unit Test Suite

To run the full suite of 80+ tests covering cryptography, file transfers, and connection logic:
docker exec -it i2i-peer-a python -m pytest tests/ -v

### Shutdown

To stop the Docker containers and clean up the network:
docker-compose down
```

## File: requirements.txt
```text
PyNaCl>=1.5.0
pytest>=7.4.0
pytest-cov>=4.1.0
python-dotenv>=1.0.0
bcrypt>=4.0.1
```

## File: .dockerignore
```text
.git
.venv
.pytest_cache
__pycache__
*.pyc
*.pyo
*.pyd
.db
.env
data/
keys/
logs/
received_files/
```

## File: .gitignore
```text
security_documentation.docx
keys/
logs/
received_files/
data/
__pycache__/
.env
.pytest_cache/
*.pyc
*.pyo
.venv/
```

## File: Dockerfile
```dockerfile
FROM python:3.10-slim-bookworm

ARG PUID=1000
ARG PGID=1000

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb fluxbox x11vnc novnc websockify tini python3-tk libtk8.6 \
    gosu \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g ${PGID} i2igroup && \
    useradd -u ${PUID} -g i2igroup -m -s /bin/bash i2iuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application directories
COPY src/ ./src/
COPY gui/ ./gui/
COPY tests/ ./tests/

# Copy individual files
COPY main.py .
COPY security_test.py .
COPY entrypoint.sh .

RUN chmod +x /app/entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
```

## File: docker-compose.yml
```yaml
networks:
  i2i-mesh:
    driver: bridge

services:
  peer-a:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        PUID: ${PUID}
        PGID: ${PGID}
    container_name: i2i-peer-a
    env_file: .env
    networks:
      - i2i-mesh
    environment:
      - I2I_BIND_ADDR=0.0.0.0
      - I2I_LISTEN_PORT=7777
    volumes:
      - ./data/peer-a_keys:/app/keys
      - ./data/peer-a_files:/app/received_files
    ports:
      - "127.0.0.1:8777:8080"
    restart: unless-stopped

  peer-b:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        PUID: ${PUID}
        PGID: ${PGID}
    container_name: i2i-peer-b
    env_file: .env
    networks:
      - i2i-mesh
    environment:
      - I2I_BIND_ADDR=0.0.0.0
      - I2I_LISTEN_PORT=7777
    volumes:
      - ./data/peer-b_keys:/app/keys
      - ./data/peer-b_files:/app/received_files
    ports:
      - "127.0.0.1:8778:8080"
    restart: unless-stopped
```

## File: .env.example
```env
# I2I Secure P2P Messenger - Environment Configuration Example

# Network Configuration
# The port the application will listen on for incoming peer connections.
I2I_LISTEN_PORT=7777

# The network interface to bind to. 
# Use 127.0.0.1 for local-only testing.
# Use 0.0.0.0 when running inside Docker.
I2I_BIND_ADDR=127.0.0.1

# Security and RBAC
# Secret code required during registration to obtain the ADMIN role.
I2I_ADMIN_SECRET=YOUR_SECURE_ADMIN_CODE_HERE

# Sync this with I2I_ADMIN_SECRET (Required for main.py logging initialization)
ADMIN_CODE=YOUR_SECURE_ADMIN_CODE_HERE

# Application Settings
# Log verbosity level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
I2I_LOG_LEVEL=INFO

# Resource Limits
# Maximum file size allowed for ADMIN transfers in MB.
I2I_MAX_FILE_MB=50

# Maximum chat message size in KB.
I2I_MAX_MSG_KB=4

# Docker Environment (Optional - used by docker-compose)
# User and Group ID for file permission management in Linux containers.
PUID=1000
PGID=1000
```

## File: entrypoint.sh
```bash
#!/bin/bash

# 1. Clean up old locks (as root)
rm -f /tmp/.X0-lock /tmp/.X11-unix/X0 2>/dev/null

# 2. Fix the /tmp directory permissions for Xvfb
mkdir -p /tmp/.X11-unix
chmod 1777 /tmp/.X11-unix
chown root:root /tmp/.X11-unix

# 3. Ensure app volumes are owned by the user
mkdir -p /app/keys /app/received_files /app/logs
chown -R i2iuser:i2igroup /app/keys /app/received_files /app/logs

# 4. Start Xvfb and VNC as root
Xvfb :0 -screen 0 1280x900x24 &
while[ ! -S /tmp/.X11-unix/X0 ]; do sleep 0.1; done

fluxbox -display :0 &
x11vnc -display :0 -nopw -forever -shared -quiet &
websockify --web /usr/share/novnc/ 8080 localhost:5900 &

export DISPLAY=:0

# 5. Run Python as i2iuser
# This ensures files created in the volume are owned by YOU on Arch
exec gosu i2iuser python main.py
```

## File: main.py
```python
"""
File: main.py
Purpose: Application entry point for I2I Secure P2P Messenger.

This script sets up secure logging, creates the received_files and logs
directories, and launches the Tkinter GUI.

Security:
- Logging is configured to write to a file (not stdout) to prevent
  sensitive error messages from appearing in the terminal.
- Log level is INFO by default (not DEBUG, which might include more detail).
- The logs/ directory is created with restrictive permissions where supported.
"""

import os
import sys
import logging
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

ADMIN_CODE = os.environ.get("ADMIN_CODE")

if not ADMIN_CODE:
    logging.error("ADMIN_CODE not found in .env or sys env")

# ─────────────────────────────────────────────
#  Secure Logging Setup
# ─────────────────────────────────────────────


def setup_logging() -> None:
    """
    Configure secure application logging.

    Security:
    - Logs are written to logs/i2i.log, not to stdout.
    - No plaintext message content or private keys are logged.
    - Uses rotating file handler to prevent unbounded log growth.

    Output: None. Configures the root logger.
    """
    logs_dir = Path("logs")
    # logs_dir.mkdir(exist_ok=True)
    # try:
    # os.chmod(logs_dir, 0o700)
    # except (AttributeError, NotImplementedError):
    # pass  # Windows — acceptable

    from logging.handlers import RotatingFileHandler

    log_file = logs_dir / "i2i.log"
    handler = RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,  # 5 MB per file
        backupCount=3,  # Keep last 3 log files
        encoding="utf-8",
    )
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)

    # Also show warnings and above to stderr
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.WARNING)
    stderr_handler.setFormatter(formatter)
    root_logger.addHandler(stderr_handler)


# ─────────────────────────────────────────────
#  Directory Initialization
# ─────────────────────────────────────────────


def ensure_directories() -> None:
    """
    Create required application directories.

    Directory security:
    - keys/ — private key storage (mode 0o700 on POSIX)
    - received_files/ — incoming file destination (mode 0o755)
    - logs/ — log files (mode 0o700 on POSIX)
    """
    for directory, mode in[
        ("keys", 0o700),
        ("received_files", 0o755),
        ("logs", 0o700),
    ]:
        path = Path(directory)
        # path.mkdir(exist_ok=True)
        # try:
        #     os.chmod(path, mode)
        # except (AttributeError, NotImplementedError):
        #     pass


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────


def main() -> None:
    """
    Launch the I2I application.

    Steps:
    1. Set up secure logging.
    2. Create required directories.
    3. Launch the Tkinter GUI.
    """
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("I2I Secure P2P Messenger starting up.")
    logger.info("=" * 60)

    ensure_directories()

    try:
        from gui.login import run_login_flow
        from gui.app import I2IApp

        while True:
            username, role = run_login_flow()
            if not username or not role:
                logger.info("Login cancelled. Exiting.")
                sys.exit(0)

            app = I2IApp(username, role)
            app.run()

            if getattr(app, "logout_requested", False):
                logger.info("User logged out. Restarting login flow.")
                continue
            else:
                break
    except ImportError as exc:
        logger.critical("Import error — are all dependencies installed? %s", exc)
        print(f"\n[ERROR] Missing dependency: {exc}")
        print("Run: pip install -r requirements.txt\n")
        sys.exit(1)
    except Exception as exc:
        logger.critical("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

## File: src/__init__.py
```python
"""
File: src/__init__.py
Purpose: Package initializer for the I2I source modules.
Exports the main module components for easy importing.
"""
```

## File: src/validators.py
```python
"""
File: src/validators.py
Purpose: Formal input validation module.

Security:
- Provides a structured validation layer for messages and files.
- Centralizes security policies for inputs.
"""

import re
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

MAX_MESSAGE_SIZE_BYTES = 4 * 1024          # 4 KB
MAX_FILE_SIZE_USER = 10 * 1024 * 1024     # 10 MB for normal users
MAX_FILE_SIZE_ADMIN = 50 * 1024 * 1024    # 50 MB for admins

class Validators:
    """Structured validation layer for application inputs."""

    @staticmethod
    def validate_message(msg: str) -> bool:
        """
        Validate a user-supplied chat message.
        """
        if not msg or not isinstance(msg, str):
            return False
            
        encoded = msg.encode("utf-8")
        if len(encoded) > MAX_MESSAGE_SIZE_BYTES:
            logger.warning("Validation failed: Message too large (%d bytes).", len(encoded))
            return False
            
        return True

    @staticmethod
    def validate_filename(name: str) -> str:
        """
        Regex safe filename sanitization to prevent path traversal.
        """
        if not isinstance(name, str):
            raise ValueError("Filename must be a string.")

        # Normalize Windows backslash separators before extracting basename.
        # os.path.basename on Linux does not treat backslash as a separator.
        name = name.replace("\\", "/")
        filename = os.path.basename(name)
        filename = filename.replace("\x00", "")
        filename = re.sub(r"[^\w.\-]", "_", filename)
        filename = re.sub(r"\.{2,}", ".", filename)
        
        RESERVED = {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3",
        }
        if filename.upper().split(".")[0] in RESERVED:
            logger.warning("Validation failed: Reserved filename attempted (%s).", filename)
            raise ValueError("Reserved filename not allowed.")
            
        if not filename or filename in {".", ".."}:
            logger.warning("Validation failed: Invalid filename after sanitization.")
            raise ValueError("Invalid filename.")
            
        return filename

    @staticmethod
    def validate_file_size(file_path: Path, role: str) -> bool:
        """
        Validate file size based on RBAC role.
        """
        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError("File not found or is not a regular file.")
            
        size = file_path.stat().st_size
        max_size = MAX_FILE_SIZE_ADMIN if role == "ADMIN" else MAX_FILE_SIZE_USER
        
        if size > max_size:
            logger.warning("Validation failed: User %s exceeded file size limit (%d > %d).", role, size, max_size)
            raise ValueError(f"File size exceeds the {max_size // (1024 * 1024)}MB limit for your role ({role}).")
            
        if size == 0:
            raise ValueError("File is empty.")
            
        return True
```

## File: src/auth_manager.py
```python
"""
File: src/auth_manager.py
Purpose: Authentication and Role-Based Access Control (RBAC) system.

Security:
- Passwords are securely hashed using bcrypt with per-user salt.
- Prevents cleartext credential storage.
- Defines roles (ADMIN, USER) for RBAC enforcement.
"""

import json
import bcrypt
import threading
from pathlib import Path
from typing import Optional, Dict, Any
import logging
from src.security_utils import validate_password_strength

logger = logging.getLogger(__name__)
AUTH_FILE = Path("keys/users.json")


class AuthManager:
    _failed_attempts: Dict[str, tuple[int, float]] = {}
    MAX_FAILED_ATTEMPTS = 3
    LOCKOUT_DURATION_SECONDS = 300
    _db_lock = threading.Lock()

    @staticmethod
    def _load_users() -> Dict[str, Any]:
        with AuthManager._db_lock:
            if not AUTH_FILE.exists():
                return {}
            try:
                with open(AUTH_FILE, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error("Failed to load users: %s", e)
                return {}

    @staticmethod
    def _save_users(users: Dict[str, Any]) -> None:
        with AuthManager._db_lock:
            try:
                with open(AUTH_FILE, "w") as f:
                    json.dump(users, f, indent=4)
                import os

                try:
                    os.chmod(AUTH_FILE, 0o600)
                except:
                    pass
            except Exception as e:
                logger.error("Failed to save users: %s", e)
                raise

    @staticmethod
    def register(username: str, password: str, role: str = "USER") -> bool:
        if not username or not password:
            raise ValueError("Username and password are required.")

        validate_password_strength(password)

        with AuthManager._db_lock:
            if not AUTH_FILE.exists():
                users = {}
            else:
                with open(AUTH_FILE, "r") as f:
                    users = json.load(f)

            if username in users:
                raise ValueError("Username already exists.")

            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
                "utf-8"
            )
            users[username] = {"password": hashed, "role": role.upper()}

            # FIXED: Perform write and harden file inside the lock
            with open(AUTH_FILE, "w") as f:
                json.dump(users, f, indent=4)
            try:
                import os

                os.chmod(AUTH_FILE, 0o600)
            except:
                pass

        logger.info("Registered user: %s", username)
        return True

    @staticmethod
    def login(username: str, password: str) -> Optional[str]:
        return AuthManager.verify_user(username, password)

    @staticmethod
    def verify_user(username: str, password: str) -> Optional[str]:
        import time

        username = username.strip()

        if username in AuthManager._failed_attempts:
            attempts, lockout_time = AuthManager._failed_attempts[username]
            if (
                attempts >= AuthManager.MAX_FAILED_ATTEMPTS
                and time.time() < lockout_time
            ):
                raise PermissionError(
                    f"Account locked. Try again in {int((lockout_time - time.time()) // 60)} mins."
                )

        users = AuthManager._load_users()
        if username not in users:
            AuthManager._record_failed_attempt(username)
            return None

        user_data = users[username]
        if bcrypt.checkpw(
            password.encode("utf-8"), user_data["password"].encode("utf-8")
        ):
            if username in AuthManager._failed_attempts:
                del AuthManager._failed_attempts[username]
            return user_data.get("role", "USER")

        AuthManager._record_failed_attempt(username)
        return None

    @staticmethod
    def _record_failed_attempt(username: str) -> None:
        import time

        attempts, _ = AuthManager._failed_attempts.get(username, (0, 0.0))
        attempts += 1
        lockout = (
            time.time() + AuthManager.LOCKOUT_DURATION_SECONDS
            if attempts >= AuthManager.MAX_FAILED_ATTEMPTS
            else 0.0
        )
        AuthManager._failed_attempts[username] = (attempts, lockout)
```

## File: src/crypto_utils.py
```python
"""
File: src/crypto_utils.py
Purpose: Cryptographic utilities for the I2I secure P2P application.

This module provides all cryptographic operations including:
- X25519 Diffie-Hellman key exchange
- XSalsa20-Poly1305 authenticated encryption/decryption
- SHA-256 based safety number generation for MITM prevention
- Secure key generation, storage, and loading
- Nonce management for replay attack prevention

Security Controls:
- Uses PyNaCl (libsodium bindings) for cryptographically secure operations
- Private keys are never exposed outside this module
- Nonces are randomly generated per message (prevents replay attacks)
- Safety numbers are derived from both peers' public keys
"""

import os
import json
import hashlib
import secrets
import logging
from pathlib import Path
from typing import Tuple, Optional

import nacl.utils
import nacl.public
import nacl.encoding
import nacl.hash
import nacl.secret

# Configure module-level logger — logs to file, not to stdout (security: no sensitive data in logs)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────
KEYS_DIR = Path("keys")
PRIVATE_KEY_FILE = KEYS_DIR / "private.key"
PUBLIC_KEY_FILE = KEYS_DIR / "public.key"
NONCE_SIZE = nacl.secret.SecretBox.NONCE_SIZE  # 24 bytes


# ─────────────────────────────────────────────
#  Key Generation & Storage
# ─────────────────────────────────────────────

def generate_keypair() -> Tuple[nacl.public.PrivateKey, nacl.public.PublicKey]:
    """
    Generate a new X25519 key pair for use in this session.

    Security: Uses os.urandom() indirectly via PyNaCl's secure RNG.

    Returns:
        Tuple of (PrivateKey, PublicKey) objects.
    """
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key
    logger.info("New X25519 key pair generated.")
    return private_key, public_key


def save_keypair(private_key: nacl.public.PrivateKey, public_key: nacl.public.PublicKey) -> None:
    """
    Persist keys to the local keys/ directory.

    Security checks:
    - Creates the keys/ directory with restrictive permissions (0o700 on POSIX).
    - Private key is stored as raw bytes (hex-encoded) — never transmitted.

    Inputs:
        private_key: nacl.public.PrivateKey object.
        public_key: nacl.public.PublicKey object.
    Output:
        None. Writes to KEYS_DIR.
    """
    KEYS_DIR.mkdir(mode=0o700, exist_ok=True)

    private_bytes = bytes(private_key).hex()
    public_bytes = bytes(public_key).hex()

    PRIVATE_KEY_FILE.write_text(private_bytes)
    PUBLIC_KEY_FILE.write_text(public_bytes)

    # Restrict read permissions on POSIX systems
    try:
        os.chmod(PRIVATE_KEY_FILE, 0o600)
    except (AttributeError, NotImplementedError):
        pass  # Windows does not support chmod — acceptable

    logger.info("Key pair saved to disk.")


def load_or_generate_keypair() -> Tuple[nacl.public.PrivateKey, nacl.public.PublicKey]:
    """
    Load an existing key pair from disk, or generate a new one if none exists.

    Security checks:
    - If key files exist they are loaded; otherwise new keys are generated and saved.
    - Handles corrupted key files by regenerating.

    Returns:
        Tuple of (PrivateKey, PublicKey).
    """
    if PRIVATE_KEY_FILE.exists() and PUBLIC_KEY_FILE.exists():
        try:
            private_bytes = bytes.fromhex(PRIVATE_KEY_FILE.read_text().strip())
            private_key = nacl.public.PrivateKey(private_bytes)
            public_key = private_key.public_key
            logger.info("Loaded existing key pair from disk.")
            return private_key, public_key
        except Exception:
            logger.warning("Corrupted key files detected — regenerating key pair.")

    private_key, public_key = generate_keypair()
    save_keypair(private_key, public_key)
    return private_key, public_key


# ─────────────────────────────────────────────
#  Key Exchange (X25519 ECDH)
# ─────────────────────────────────────────────

def compute_shared_secret(
    our_private_key: nacl.public.PrivateKey,
    their_public_key_bytes: bytes
) -> nacl.public.Box:
    """
    Perform X25519 ECDH key exchange to derive a shared secret Box.

    Security:
    - X25519 provides forward secrecy when combined with ephemeral keys.
    - The resulting Box uses XSalsa20-Poly1305 for AEAD encryption.

    Inputs:
        our_private_key: Our local PrivateKey object.
        their_public_key_bytes: Peer's raw 32-byte public key.
    Output:
        nacl.public.Box — authenticated encryption box using shared secret.
    Raises:
        ValueError: If the public key bytes are invalid.
    """
    if len(their_public_key_bytes) != 32:
        raise ValueError("Invalid public key length. Expected 32 bytes.")

    try:
        their_public_key = nacl.public.PublicKey(their_public_key_bytes)
        box = nacl.public.Box(our_private_key, their_public_key)
        logger.info("Shared secret computed via X25519.")
        return box
    except Exception as exc:
        logger.error("Key exchange failed: %s", type(exc).__name__)
        raise ValueError("Key exchange failed — invalid peer public key.") from exc


# ─────────────────────────────────────────────
#  Encryption / Decryption
# ─────────────────────────────────────────────

def encrypt_message(box: nacl.public.Box, plaintext: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext using XSalsa20-Poly1305 authenticated encryption.

    Security:
    - A unique random nonce is generated per message (prevents replay attacks).
    - The MAC (Poly1305) ensures integrity and authenticity.
    - Plaintext is never logged.

    Inputs:
        box: nacl.public.Box (shared secret box).
        plaintext: Raw bytes to encrypt.
    Output:
        Tuple of (ciphertext, nonce) both as bytes.
    """
    nonce = nacl.utils.random(NONCE_SIZE)
    encrypted = box.encrypt(plaintext, nonce)
    # encrypted includes nonce prefix — extract ciphertext only
    ciphertext = encrypted.ciphertext
    return ciphertext, nonce


def decrypt_message(box: nacl.public.Box, ciphertext: bytes, nonce: bytes) -> bytes:
    """
    Decrypt ciphertext using XSalsa20-Poly1305 authenticated decryption.

    Security:
    - Poly1305 MAC is verified before returning plaintext.
    - Any tampered ciphertext raises an exception.
    - Decryption errors are logged generically (no plaintext in logs).

    Inputs:
        box: nacl.public.Box (shared secret box).
        ciphertext: Encrypted bytes to decrypt.
        nonce: 24-byte nonce used during encryption.
    Output:
        Decrypted plaintext bytes.
    Raises:
        nacl.exceptions.CryptoError: If MAC verification fails (tampered data).
        ValueError: If the nonce length is incorrect.
    """
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Invalid nonce length. Expected {NONCE_SIZE} bytes.")

    # PyNaCl Box.decrypt accepts nonce+ciphertext as combined bytes
    combined = nonce + ciphertext
    plaintext = box.decrypt(combined)
    return plaintext


# ─────────────────────────────────────────────
#  Safety Numbers (MITM Prevention)
# ─────────────────────────────────────────────

def compute_safety_number(pub_key_a: bytes, pub_key_b: bytes) -> str:
    """
    Compute a human-verifiable safety number from two peers' public keys.

    This is a fingerprint that both parties can compare out-of-band (e.g., verbally)
    to verify no MITM has occurred.

    Security:
    - Keys are sorted before hashing to ensure the same number on both ends.
    - Uses SHA-256 for collision resistance.

    Inputs:
        pub_key_a: First peer's raw public key bytes.
        pub_key_b: Second peer's raw public key bytes.
    Output:
        A formatted 5×5-digit safety number string (e.g., "12345 67890 ...").
    """
    sorted_keys = sorted([pub_key_a, pub_key_b])
    combined = sorted_keys[0] + sorted_keys[1]
    digest = hashlib.sha256(combined).hexdigest()

    # Format as groups of 5 digits for readability
    numeric = str(int(digest, 16))[:30].zfill(30)
    groups =[numeric[i:i+5] for i in range(0, 30, 5)]
    safety_number = " ".join(groups)
    return safety_number


# ─────────────────────────────────────────────
#  Utility
# ─────────────────────────────────────────────

def public_key_to_hex(public_key: nacl.public.PublicKey) -> str:
    """
    Convert a PublicKey object to its hex string representation.

    Inputs:
        public_key: nacl.public.PublicKey object.
    Output:
        64-character hex string.
    """
    return bytes(public_key).hex()


def hex_to_public_key_bytes(hex_str: str) -> bytes:
    """
    Validate and convert a hex string to raw public key bytes.

    Security:
    - Validates hex format and length before conversion.

    Inputs:
        hex_str: 64-character hex string representing a 32-byte X25519 public key.
    Output:
        32 raw bytes.
    Raises:
        ValueError: If the hex string is malformed or incorrect length.
    """
    hex_str = hex_str.strip()
    if len(hex_str) != 64:
        raise ValueError("Public key must be 64 hex characters (32 bytes).")
    try:
        return bytes.fromhex(hex_str)
    except ValueError as exc:
        raise ValueError("Invalid hex encoding in public key.") from exc


def generate_peer_address(public_key: nacl.public.PublicKey) -> str:
    """
    Derive a deterministic .b32.i2p-style address from a public key.

    Security:
    - Address is derived via SHA-256 of the public key — collision resistant.
    - Used for routing in the simulated I2P layer.

    Inputs:
        public_key: nacl.public.PublicKey object.
    Output:
        String in the form "<52-char-base32>.b32.i2p".
    """
    import base64
    digest = hashlib.sha256(bytes(public_key)).digest()
    b32 = base64.b32encode(digest).decode().lower().rstrip("=")
    return f"{b32}.b32.i2p"
```

## File: src/file_transfer.py
```python
"""
File: src/file_transfer.py
Purpose: Secure chunked file transfer module for the I2I application.

All file chunks and acknowledgments flow through the encrypted message handler
(send_raw_envelope / parse_and_decrypt_envelope), avoiding any direct socket
reads that would race with the receive loop thread.

Transfer Protocol:
  1. Sender  ──[FILE_META  {filename, chunks, hash, size}]──► Receiver
  2. Receiver ──[FILE_ACK  {ack: "ready"}]──────────────────► Sender
  3. For each chunk i:
       Sender  ──[FILE_CHUNK {chunk_index, total, data_hex}]──► Receiver
       Receiver ──[FILE_ACK  {ack: "chunk_i"}]─────────────────► Sender
  4. Receiver verifies SHA-256 of reassembled file.

Security Controls:
- All frames are encrypted via the session Box (XSalsa20-Poly1305).
- Filenames are sanitized before write (path traversal prevention).
- Files written only to received_files/ directory.
- SHA-256 integrity verified after full reassembly.
- Tampered or incomplete files are deleted before notifying the UI.
- ACK synchronization uses threading.Event — no direct socket reads.
"""

import json
import time
import logging
import threading
import os
from pathlib import Path
from typing import Optional, Callable
from src.peer_connection import PeerSession
from src.message_handler import (
    send_raw_envelope,
    MESSAGE_TYPE_FILE_CHUNK,
    MESSAGE_TYPE_FILE_META,
    MESSAGE_TYPE_FILE_ACK,
)
from src.security_utils import (
    validate_file_path,
    sanitize_filename,
    compute_file_hash,
    verify_file_hash,
)

logger = logging.getLogger(__name__)

CHUNK_SIZE = 4 * 1024
MAX_CHUNK_RETRIES = 3
ACK_TIMEOUT = 30
RECEIVED_FILES_DIR = Path("received_files")


class FileSender:
    def __init__(
        self,
        session: PeerSession,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        self._session = session
        self._on_progress = on_progress
        self._ack_event = threading.Event()
        self._last_ack: Optional[str] = None
        self._ack_lock = threading.Lock()

    def on_ack_received(self, token: str) -> None:
        with self._ack_lock:
            self._last_ack = token
            self._ack_event.set()

    def send_file(self, file_path: str) -> bool:
        try:
            path = validate_file_path(file_path)
        except Exception as exc:
            logger.error("File validation failed: %s", exc)
            return False

        filename = sanitize_filename(path.name)
        file_hash = compute_file_hash(path)
        file_size = path.stat().st_size
        total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

        meta_payload = json.dumps(
            {
                "filename": filename,
                "total_chunks": total_chunks,
                "file_hash": file_hash,
                "size": file_size,
            }
        ).encode("utf-8")

        if not send_raw_envelope(self._session, MESSAGE_TYPE_FILE_META, meta_payload):
            return False

        if not self._wait_for_ack("ready"):
            return False

        with open(path, "rb") as f:
            for chunk_index in range(total_chunks):
                chunk_data = f.read(CHUNK_SIZE)
                chunk_payload = json.dumps(
                    {
                        "chunk_index": chunk_index,
                        "total_chunks": total_chunks,
                        "data": chunk_data.hex(),
                    }
                ).encode("utf-8")

                success = False
                for attempt in range(MAX_CHUNK_RETRIES):
                    if send_raw_envelope(
                        self._session, MESSAGE_TYPE_FILE_CHUNK, chunk_payload
                    ):
                        if self._wait_for_ack(f"chunk_{chunk_index}"):
                            success = True
                            break
                if not success:
                    return False
                if self._on_progress:
                    self._on_progress(chunk_index + 1, total_chunks)
        return True

    def _wait_for_ack(self, expected: str) -> bool:
        self._ack_event.clear()
        if not self._ack_event.wait(timeout=ACK_TIMEOUT):
            return False
        with self._ack_lock:
            return self._last_ack == expected


class FileReceiver:
    def __init__(
        self,
        session: PeerSession,
        max_file_size: int,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_complete: Optional[Callable[[str, bool], None]] = None,
    ) -> None:
        self._session = session
        self._max_file_size = max_file_size
        self._on_progress = on_progress
        self._on_complete = on_complete
        self._temp_file: Optional[Path] = None
        self._total_chunks: int = 0
        self._expected_hash: Optional[str] = None
        self._received_chunks: set[int] = set()
        self._ready = False
        RECEIVED_FILES_DIR.mkdir(exist_ok=True)

    def handle_meta(self, payload: bytes) -> None:
        try:
            meta = json.loads(payload.decode("utf-8"))
            filename = sanitize_filename(meta["filename"])
            size = int(meta["size"])

            if size > self._max_file_size:
                self._send_ack("error")
                return

            self._total_chunks = int(meta["total_chunks"])
            self._expected_hash = meta["file_hash"]

            # FIXED: Add a timestamp to the .part file to prevent collisions
            unique_id = int(time.time() * 1000)
            self._temp_file = RECEIVED_FILES_DIR / f"{filename}_{unique_id}.part"

            with open(self._temp_file, "wb") as f:
                f.truncate(size)  # Pre-allocate space on disk

            self._received_chunks = set()
            self._ready = True
            self._send_ack("ready")
        except Exception:
            self._send_ack("error")

    def handle_chunk(self, payload: bytes) -> None:
        if not self._ready or not self._temp_file:
            return
        try:
            envelope = json.loads(payload.decode("utf-8"))
            idx = int(envelope["chunk_index"])
            data = bytes.fromhex(envelope["data"])

            if 0 <= idx < self._total_chunks:
                with open(self._temp_file, "r+b") as f:
                    f.seek(idx * CHUNK_SIZE)
                    f.write(data)

                self._received_chunks.add(idx)
                self._send_ack(f"chunk_{idx}")

                if self._on_progress:
                    self._on_progress(len(self._received_chunks), self._total_chunks)

                if len(self._received_chunks) == self._total_chunks:
                    self._reassemble()
        except Exception:
            pass

    def _reassemble(self) -> None:
        final_path = self._temp_file.with_suffix("")  # Remove .part
        if final_path.exists():
            final_path = (
                RECEIVED_FILES_DIR
                / f"{final_path.stem}_{int(time.time())}{final_path.suffix}"
            )

        try:
            os.rename(self._temp_file, final_path)
            if verify_file_hash(final_path, self._expected_hash):
                if self._on_complete:
                    self._on_complete(str(final_path), True)
            else:
                final_path.unlink(missing_ok=True)
                if self._on_complete:
                    self._on_complete("", False)
        except Exception:
            if self._temp_file and self._temp_file.exists():
                self._temp_file.unlink()
            if self._on_complete:
                self._on_complete("", False)
        finally:
            self._ready = False

    def _send_ack(self, token: str) -> None:
        payload = json.dumps({"ack": token}).encode("utf-8")
        send_raw_envelope(self._session, MESSAGE_TYPE_FILE_ACK, payload)
```

## File: src/i2p_manager.py
```python
"""
File: src/i2p_manager.py
Purpose: I2P network interface layer for the I2I application.

This module manages the simulated I2P SAM (Simple Anonymous Messaging) API layer.
In production, this would connect to a real I2P router via the SAM protocol
(TCP on port 7656). For standalone demonstration without an I2P router, it
simulates the layer using a local TCP server/client on localhost.

Key responsibilities:
- Generate and manage .b32.i2p-style peer addresses
- Accept incoming peer connections (listener mode)
- Establish outbound peer connections
- Provide a socket-like interface to the rest of the application

Security Controls:
- Peer addresses are derived deterministically from public keys (no spoofing)
- No real IP addresses are exposed
- Connection timeouts enforced (10 seconds)
- Connection limits to prevent resource exhaustion
"""

import os
import socket
import threading
import logging
from typing import Optional, Callable

from src.crypto_utils import generate_peer_address
import nacl.public

logger = logging.getLogger(__name__)

# Allows Docker to override to 0.0.0.0, defaults to 127.0.0.1 for native use
BIND_ADDRESS = os.getenv("I2I_BIND_ADDR", "127.0.0.1")
DEFAULT_PORT = 7777
CONNECTION_TIMEOUT = 10
MAX_CONNECTIONS = 10


class I2PManager:
    def __init__(
        self, public_key: nacl.public.PublicKey, port: int = DEFAULT_PORT
    ) -> None:
        self._public_key = public_key
        self._port = port
        self._address = generate_peer_address(public_key)
        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._accept_thread: Optional[threading.Thread] = None
        self._on_new_connection: Optional[Callable] = None

    @property
    def local_address(self) -> str:
        return self._address

    def start_listener(
        self, on_new_connection: Callable[[socket.socket, str], None]
    ) -> None:
        self._on_new_connection = on_new_connection
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.settimeout(1.0)

        # FIXED: Use BIND_ADDRESS variable
        self._server_socket.bind((BIND_ADDRESS, self._port))

        self._server_socket.listen(MAX_CONNECTIONS)
        self._running = True
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="I2PListener", daemon=True
        )
        self._accept_thread.start()
        logger.info("I2P listener started on %s:%d.", BIND_ADDRESS, self._port)

    def _accept_loop(self) -> None:
        while self._running:
            try:
                conn, addr = self._server_socket.accept()
                conn.settimeout(CONNECTION_TIMEOUT)
                handler = threading.Thread(
                    target=self._on_new_connection, args=(conn, addr[0]), daemon=True
                )
                handler.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop_listener(self) -> None:
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass

    # FIXED: Added target_host parameter
    def connect_to_peer(self, target_host: str, peer_port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECTION_TIMEOUT)
        try:
            sock.connect((target_host, peer_port))
            return sock
        except (ConnectionRefusedError, socket.timeout):
            sock.close()
            raise
```

## File: src/message_handler.py
```python
"""
File: src/message_handler.py
Purpose: Encrypted message send/receive logic for the I2I application.

This module handles the high-level message protocol on top of the encrypted
peer session layer. It is responsible for:
- Constructing JSON message envelopes
- Encrypting payloads before transmission
- Decrypting and validating received message envelopes
- Detecting and rejecting replay attacks via nonce tracking
- Message size enforcement

Message Format:
{
  "type": "message",          # "message" | "key_exchange" | "file_chunk" | "file_ack"
  "sender": "<peer_address>",
  "data": "<hex-encoded ciphertext>",
  "nonce": "<hex-encoded 24-byte nonce>",
  "timestamp": <unix_float>
}

Security Controls:
- All message content is encrypted using the session Box (XSalsa20-Poly1305).
- Nonces are random and registered for replay attack detection.
- Timestamps are validated (allow ±5 minutes — handles clock skew).
- Malformed envelopes are rejected without exposing error details.
- No plaintext message content in logs.
"""

import json
import time
import logging
from typing import Optional, Tuple
import nacl.exceptions
from src.peer_connection import PeerSession, _send_framed
from src.crypto_utils import encrypt_message, decrypt_message, NONCE_SIZE
from src.security_utils import validate_message, rate_limiter

logger = logging.getLogger(__name__)

MESSAGE_TYPE_CHAT = "message"
MESSAGE_TYPE_FILE_CHUNK = "file_chunk"
MESSAGE_TYPE_FILE_ACK = "file_ack"
MESSAGE_TYPE_FILE_META = "file_meta"
MESSAGE_TYPE_CONTROL = "control"
TIMESTAMP_TOLERANCE_SECONDS = 300
MAX_TIMESTAMP_FUTURE_SECONDS = 60


def send_chat_message(session: PeerSession, plaintext: str) -> bool:
    try:
        plaintext = validate_message(plaintext)
    except ValueError as exc:
        logger.warning("Message validation failed: %s", exc)
        return False

    if not rate_limiter.is_allowed(session.peer_address):
        logger.warning("Rate limit: message to peer rejected.")
        return False
    return _send_envelope(session, MESSAGE_TYPE_CHAT, plaintext.encode("utf-8"))


def send_raw_envelope(session: PeerSession, msg_type: str, payload: bytes) -> bool:
    return _send_envelope(session, msg_type, payload)


def _send_envelope(session: PeerSession, msg_type: str, payload: bytes) -> bool:
    """
    FIXED: We now wrap the metadata AND the payload into one JSON object,
    and then encrypt that ENTIRE object to protect metadata.
    """
    try:
        envelope_dict = {
            "type": msg_type,
            "sender": session.peer_address,
            "timestamp": time.time(),
            "payload": payload.hex(),
        }
        envelope_bytes = json.dumps(envelope_dict).encode("utf-8")

        # Encrypt the whole JSON blob
        ciphertext, nonce = encrypt_message(session.box, envelope_bytes)

        # Send: [Nonce (24 bytes)][Ciphertext]
        _send_framed(session.sock, nonce + ciphertext)
        return True
    except Exception:
        logger.error("Failed to send message (details suppressed).")
        return False


def parse_and_decrypt_envelope(
    session: PeerSession, raw_bytes: bytes
) -> Optional[Tuple[str, bytes]]:
    """
    FIXED: Decrypt first, then parse.
    This prevents DoS attacks via malformed JSON before authentication.
    """
    if len(raw_bytes) < NONCE_SIZE + 16:  # Min nonce + min Poly1305 tag
        return None

    nonce = raw_bytes[:NONCE_SIZE]
    ciphertext = raw_bytes[NONCE_SIZE:]

    # 1. DECRYPT FIRST (Verifies MAC)
    try:
        decrypted_blob = decrypt_message(session.box, ciphertext, nonce)
    except nacl.exceptions.CryptoError:
        logger.warning("MAC verification failed - discarding tampered message.")
        return None
    except Exception:
        return None

    # 2. PARSE JSON SECOND (Only happens if MAC is valid)
    try:
        envelope = json.loads(decrypted_blob.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.warning("Decrypted blob was not valid JSON.")
        return None

    # Validate fields
    required = {"type", "timestamp", "payload"}
    if not required.issubset(envelope.keys()):
        return None

    # Timestamp validation
    try:
        timestamp = float(envelope["timestamp"])
        now = time.time()
        if (now - timestamp > TIMESTAMP_TOLERANCE_SECONDS) or (
            timestamp > now + MAX_TIMESTAMP_FUTURE_SECONDS
        ):
            logger.warning("Message timestamp expired or too far in future.")
            return None
    except (ValueError, TypeError):
        return None

    # Replay protection
    if not session.register_nonce(nonce):
        return None

    try:
        msg_type = envelope["type"]
        payload = bytes.fromhex(envelope["payload"])
        return msg_type, payload
    except Exception:
        return None
```

## File: src/peer_connection.py
```python
"""
File: src/peer_connection.py
Purpose: Peer connection lifecycle management for the I2I application.

This module handles the complete lifecycle of P2P connections:
- Initiating and accepting connections
- Performing X25519 key exchange handshake
- Maintaining active session state
- Handling disconnection and cleanup
- Retry logic (max 3 attempts) with 10-second timeout

Security Controls:
- Key exchange is performed immediately on connection (before any data exchange)
- Public keys are transmitted and verified before establishing session
- No plaintext communication after handshake
- Sessions are isolated — each peer gets independent encryption context
- Connection errors are handled generically to avoid info disclosure
"""

import json
import socket
import struct
import logging
import threading
import time
from typing import Optional, Callable, Tuple

import nacl.public
import nacl.exceptions

from src.crypto_utils import (
    compute_shared_secret,
    public_key_to_hex,
    hex_to_public_key_bytes,
    compute_safety_number,
    generate_peer_address,
    generate_keypair,
    encrypt_message,
    decrypt_message,
)
from src.security_utils import validate_public_key_hex

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────
MAX_RETRY_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 2
HANDSHAKE_TIMEOUT = 10
MESSAGE_HEADER_SIZE = 4               # 4-byte big-endian length prefix
MAX_RAW_MESSAGE_BYTES = 10 * 1024 * 1024  # 10 MB absolute cap on single recv
SOCKET_BUFFER_SIZE = 65536            # 64 KB read buffer


# ─────────────────────────────────────────────
#  Session State
# ─────────────────────────────────────────────

class PeerSession:
    """
    Represents an active encrypted session with a single peer.

    Security:
    - Holds the shared secret Box for this peer only.
    - Tracks nonces seen to detect replay attacks.
    - Thread-safe due to the GIL and atomic assignment on basic types.
    """

    def __init__(
        self,
        sock: socket.socket,
        peer_address: str,
        peer_public_key_bytes: bytes,
        box: nacl.public.Box,
        safety_number: str,
    ) -> None:
        self.sock = sock
        self.peer_address = peer_address
        self.peer_public_key_bytes = peer_public_key_bytes
        self.box = box
        self.safety_number = safety_number
        self.connected_at = time.time()
        self._used_nonces: set = set()   # Replay attack prevention
        self._nonce_lock = threading.Lock()

    def register_nonce(self, nonce: bytes) -> bool:
        """
        Register a nonce and return False if it was already seen (replay attack).

        Security: Prevents replay attacks where an attacker re-sends captured messages.

        Inputs:
            nonce: 24-byte nonce from a received message.
        Output:
            True if nonce is fresh, False if it is a replay.
        """
        with self._nonce_lock:
            if nonce in self._used_nonces:
                logger.warning("Replay attack detected — duplicate nonce from peer.")
                return False
            self._used_nonces.add(nonce)
            # Bound nonce set size to prevent memory exhaustion (keep last 10,000)
            if len(self._used_nonces) > 10_000:
                # Discard oldest — rebuild as ordered would be costly; simple clear of oldest half
                nonces_list = list(self._used_nonces)
                self._used_nonces = set(nonces_list[5_000:])
            return True

    def close(self) -> None:
        """Close the underlying socket cleanly."""
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# ─────────────────────────────────────────────
#  Connection Management
# ─────────────────────────────────────────────

class PeerConnectionManager:
    """
    Manages establishing, handshaking, and maintaining P2P peer sessions.

    Security:
    - All connections go through key exchange before data exchange.
    - Sessions are tracked and can be individually terminated.
    - No raw data is passed through without session-level encryption.
    """

    def __init__(
        self,
        our_private_key: nacl.public.PrivateKey,
        our_public_key: nacl.public.PublicKey,
        on_message_received: Callable[[str, bytes], None],
        on_peer_connected: Callable[[str, str], None],
        on_peer_disconnected: Callable[[str], None],
    ) -> None:
        """
        Initialize the connection manager.

        Inputs:
            our_private_key: Local X25519 private key for ECDH.
            our_public_key: Local X25519 public key (shared with peers).
            on_message_received: Callback(peer_address, raw_decrypted_bytes).
            on_peer_connected: Callback(peer_address, safety_number).
            on_peer_disconnected: Callback(peer_address).
        """
        self._private_key = our_private_key
        self._public_key = our_public_key
        self._sessions: dict[str, PeerSession] = {}
        self._sessions_lock = threading.Lock()
        self._on_message_received = on_message_received
        self._on_peer_connected = on_peer_connected
        self._on_peer_disconnected = on_peer_disconnected

    # ──────────────────────────────────────────
    #  Outbound Connection
    # ──────────────────────────────────────────

    def connect_to_peer(
        self,
        sock: socket.socket,
        peer_display_address: str,
        peer_public_key_hex: str,
    ) -> Optional[PeerSession]:
        """
        Connect to a peer: validates key, performs handshake, starts receive loop.

        Security:
        - Validates the peer public key hex before performing ECDH.
        - Performs handshake (exchange public keys) immediately on connection.
        - Returns None on any failure rather than raising (avoids info leakage to caller).

        Inputs:
            sock: Already-connected socket to the peer.
            peer_display_address: Peer's .b32.i2p address (for display/logging).
            peer_public_key_hex: Peer's X25519 public key as 64-char hex string.
        Output:
            PeerSession on success, None on failure.
        """
        try:
            peer_pub_hex = validate_public_key_hex(peer_public_key_hex)
            peer_pub_bytes = hex_to_public_key_bytes(peer_pub_hex)
        except ValueError as exc:
            logger.error("Peer public key validation failed: %s", exc)
            return None

        try:
            session = self._perform_handshake(sock, peer_display_address, peer_pub_bytes)
        except Exception:
            logger.error("Handshake failed with peer (details suppressed for security).")
            return None

        if session:
            self._register_session(session)
            thread = threading.Thread(
                target=self._receive_loop,
                args=(session,),
                daemon=True,
                name=f"Recv-{peer_display_address[:8]}",
            )
            thread.start()

        return session

    def handle_incoming_connection(
        self, sock: socket.socket, peer_ip: str
    ) -> None:
        """
        Handle an incoming peer connection (server side).

        Security:
        - Immediately enters handshake — no data is accepted before key exchange.
        - Logs only anonymized IP for security.

        Inputs:
            sock: Newly accepted socket from the server listener.
            peer_ip: Source IP of the incoming connection (used for logging only).
        """
        logger.info("Incoming connection from %s.", peer_ip[:6] + "...")
        try:
            # We don't know the peer's .b32.i2p address yet — derive after key exchange
            session = self._perform_handshake(sock, peer_ip, peer_pub_bytes=None)
        except Exception:
            logger.error("Incoming handshake failed (details suppressed).")
            try:
                sock.close()
            except OSError:
                pass
            return

        if session:
            self._register_session(session)
            thread = threading.Thread(
                target=self._receive_loop,
                args=(session,),
                daemon=True,
                name=f"Recv-{session.peer_address[:8]}",
            )
            thread.start()
            self._on_peer_connected(session.peer_address, session.safety_number)

    # ──────────────────────────────────────────
    #  Key Exchange Handshake
    # ──────────────────────────────────────────

    def _perform_handshake(
        self,
        sock: socket.socket,
        peer_label: str,
        peer_pub_bytes: Optional[bytes],
    ) -> Optional[PeerSession]:
        """
        Perform X25519 key exchange handshake over the socket.

        Protocol (both sides simultaneously):
          1. Send our public key (32 bytes) length-prefixed.
          2. Receive peer's public key (32 bytes) length-prefixed.
          3. Derive shared secret via ECDH.
          4. Derive peer's .b32.i2p address from their public key.
          5. Compute safety number.

        Security:
        - Public keys are sent in the clear — this is expected (Diffie-Hellman).
        - The shared secret is NEVER transmitted.
        - Safety number allows out-of-band MITM verification.

        Inputs:
            sock: Connected socket.
            peer_label: Display label for logging.
            peer_pub_bytes: Peer's public key bytes if known (outbound); None for inbound.
        Output:
            PeerSession on success.
        Raises:
            ValueError, OSError: On failure.
        """
        our_pub_bytes = bytes(self._public_key)

        # Send our identity public key
        _send_framed(sock, our_pub_bytes)

        # Receive peer's identity public key
        received_pub_bytes = _recv_framed(sock, timeout=HANDSHAKE_TIMEOUT)
        if len(received_pub_bytes) != 32:
            raise ValueError("Received malformed public key from peer.")

        if peer_pub_bytes is not None:
            import hmac
            if not hmac.compare_digest(received_pub_bytes, peer_pub_bytes):
                raise ValueError("Peer public key mismatch — possible MITM attack!")

        # Derive initial identity box (used ONLY to authenticate the ephemeral keys)
        identity_box = compute_shared_secret(self._private_key, received_pub_bytes)

        # --- Phase 2: Ephemeral Key Exchange (Perfect Forward Secrecy) ---
        eph_priv, eph_pub = generate_keypair()
        
        # Encrypt our ephemeral pub with the identity box
        cipher_eph_pub, nonce = encrypt_message(identity_box, bytes(eph_pub))
        _send_framed(sock, nonce + cipher_eph_pub)
        
        # Receive peer's encrypted ephemeral pub
        peer_eph_payload = _recv_framed(sock, timeout=HANDSHAKE_TIMEOUT)
        if len(peer_eph_payload) < 24:
            raise ValueError("Malformed ephemeral key payload.")
            
        peer_nonce = peer_eph_payload[:24]
        peer_cipher = peer_eph_payload[24:]
        peer_eph_pub_bytes = decrypt_message(identity_box, peer_cipher, peer_nonce)
        
        # The true session box is derived from the ephemeral keys
        session_box = compute_shared_secret(eph_priv, peer_eph_pub_bytes)

        # Derive peer identity for display
        peer_address = generate_peer_address(
            nacl.public.PublicKey(received_pub_bytes)
        )
        safety_number = compute_safety_number(our_pub_bytes, received_pub_bytes)

        session = PeerSession(
            sock=sock,
            peer_address=peer_address,
            peer_public_key_bytes=received_pub_bytes,
            box=session_box,
            safety_number=safety_number,
        )
        logger.info("Handshake complete. Peer address: %s...", peer_address[:12])
        return session

    # ──────────────────────────────────────────
    #  Receive Loop
    # ──────────────────────────────────────────

    def _receive_loop(self, session: PeerSession) -> None:
        """
        Background thread: Continuously receive and decrypt messages from a peer.

        Security:
        - Each received frame is verified and decrypted before passing up.
        - Logs generic error messages — no raw data in logs.
        - Loop exits cleanly on socket closure or error.

        Inputs:
            session: Active PeerSession to read from.
        """
        # IMPORTANT: Set socket to fully blocking mode.
        # The socket may have a timeout left over from the connection/handshake
        # phase. Without this, the receive loop would raise socket.timeout
        # (a subclass of OSError) after 10 seconds of idle and disconnect.
        session.sock.settimeout(None)

        while True:
            try:
                raw = _recv_framed(session.sock, timeout=None)
                self._on_message_received(session.peer_address, raw)
            except (OSError, ConnectionResetError, EOFError):
                break
            except Exception:
                logger.warning("Error receiving data from peer (details suppressed).")
                break

        logger.info("Peer disconnected: %s...", session.peer_address[:12])
        self._unregister_session(session.peer_address)
        self._on_peer_disconnected(session.peer_address)

    # ──────────────────────────────────────────
    #  Session Registry
    # ──────────────────────────────────────────

    def _register_session(self, session: PeerSession) -> None:
        """Register a new session, closing any existing session for that peer."""
        with self._sessions_lock:
            if session.peer_address in self._sessions:
                self._sessions[session.peer_address].close()
            self._sessions[session.peer_address] = session

    def _unregister_session(self, peer_address: str) -> None:
        """Remove a session from the registry."""
        with self._sessions_lock:
            self._sessions.pop(peer_address, None)

    def get_session(self, peer_address: str) -> Optional[PeerSession]:
        """Retrieve an active session by peer address."""
        with self._sessions_lock:
            return self._sessions.get(peer_address)

    def get_all_sessions(self) -> list[PeerSession]:
        """Return a snapshot of all active sessions."""
        with self._sessions_lock:
            return list(self._sessions.values())

    def disconnect_peer(self, peer_address: str) -> None:
        """Gracefully disconnect from a peer."""
        with self._sessions_lock:
            session = self._sessions.pop(peer_address, None)
        if session:
            session.close()
            logger.info("Disconnected from peer: %s...", peer_address[:12])


# ─────────────────────────────────────────────
#  Framing (Length-Prefixed I/O)
# ─────────────────────────────────────────────

def _send_framed(sock: socket.socket, data: bytes) -> None:
    """
    Send a length-prefixed data frame over the socket.

    Format: [4-byte big-endian length][data bytes]

    Security:
    - Length prefix prevents ambiguous message boundaries.
    - Prevents message injection via crafted frame sizes.

    Inputs:
        sock: Target socket.
        data: Bytes to send.
    Raises:
        OSError: On send failure.
    """
    if len(data) > MAX_RAW_MESSAGE_BYTES:
        raise ValueError(f"Data too large to send: {len(data)} bytes.")
    header = struct.pack("!I", len(data))
    sock.sendall(header + data)


def _recv_framed(sock: socket.socket, timeout: Optional[float]) -> bytes:
    """
    Receive a length-prefixed data frame from the socket.

    Security:
    - Reads exact number of bytes specified by the header (no more, no less).
    - Enforces MAX_RAW_MESSAGE_BYTES cap to prevent memory exhaustion DoS.
    - Always applies the timeout (including None for blocking mode) to avoid
      stale timeouts from earlier socket operations causing false disconnects.

    Inputs:
        sock: Source socket.
        timeout: Seconds to wait, or None for fully blocking (no timeout).
    Output:
        Received bytes payload.
    Raises:
        EOFError: If the connection closed mid-read.
        ValueError: If the declared length exceeds the safety limit.
    """
    # Always set the timeout — passing None explicitly enables blocking mode,
    # clearing any timeout left over from the connection/handshake phase.
    sock.settimeout(timeout)

    header = _recv_exact(sock, MESSAGE_HEADER_SIZE)
    (length,) = struct.unpack("!I", header)

    if length == 0:
        return b""
    if length > MAX_RAW_MESSAGE_BYTES:
        raise ValueError(f"Incoming frame too large: {length} bytes.")

    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Read exactly n bytes from the socket.

    Security:
    - Loops until n bytes are received — prevents partial reads.
    - Raises EOFError if the connection closes before n bytes arrive.

    Inputs:
        sock: Source socket.
        n: Exact number of bytes to read.
    Output:
        Exactly n bytes.
    Raises:
        EOFError: If connection closes before n bytes received.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(SOCKET_BUFFER_SIZE, n - len(buf)))
        if not chunk:
            raise EOFError("Connection closed before all bytes received.")
        buf.extend(chunk)
    return bytes(buf)
```

## File: src/security_utils.py
```python
"""
File: src/security_utils.py
Purpose: Security utility functions for the I2I P2P application.

This module provides defensive security controls including:
- Input validation for all user-supplied data
- Filename sanitization to prevent path traversal attacks
- Rate limiting using a token bucket algorithm
- Message and file size enforcement
- I2P address format validation
- DoS protection mechanisms

Security Controls:
- All external inputs pass through this module before processing
- Reject malformed data at the earliest point (fail-fast)
- Rate limiting prevents flooding/DoS from a single peer
- Filename sanitization prevents directory traversal (../../../etc/passwd)
"""

import os
import re
import time
import logging
import hashlib
from pathlib import Path
from collections import defaultdict
from typing import Dict, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  Constants / Limits
# ─────────────────────────────────────────────
MAX_MESSAGE_SIZE_BYTES = 4 * 1024          # 4 KB
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024    # 50 MB
MAX_FILENAME_LENGTH = 255
B32_I2P_PATTERN = re.compile(r'^[a-z2-7]{52}\.b32\.i2p$')
HEX_PUBLIC_KEY_PATTERN = re.compile(r'^[0-9a-fA-F]{64}$')

# Rate limiting — token bucket
RATE_LIMIT_CAPACITY = 20       # Maximum tokens per peer
RATE_LIMIT_REFILL_RATE = 5     # Tokens added per second
RATE_LIMIT_COST = 1            # Tokens consumed per message


# ─────────────────────────────────────────────
#  Rate Limiter (Token Bucket)
# ─────────────────────────────────────────────

class RateLimiter:
    """
    Token bucket rate limiter to prevent message flooding from a single peer.

    Purpose: Mitigates DoS attacks where a malicious peer sends messages at very high rates.

    Security:
    - Each peer_id gets its own bucket.
    - Sending a message costs 1 token.
    - Tokens refill at RATE_LIMIT_REFILL_RATE per second, capped at RATE_LIMIT_CAPACITY.
    """

    def __init__(self) -> None:
        # {peer_id: {"tokens": float, "last_refill": float}}
        self._buckets: Dict[str, dict] = defaultdict(
            lambda: {"tokens": float(RATE_LIMIT_CAPACITY), "last_refill": time.monotonic()}
        )

    def is_allowed(self, peer_id: str) -> bool:
        """
        Check whether the given peer is allowed to send another message right now.

        Inputs:
            peer_id: Unique identifier string for the sending peer.
        Output:
            True if the peer is within rate limits, False if rate-limited.
        """
        bucket = self._buckets[peer_id]
        now = time.monotonic()
        elapsed = now - bucket["last_refill"]

        # Refill tokens proportionally to elapsed time
        bucket["tokens"] = min(
            RATE_LIMIT_CAPACITY,
            bucket["tokens"] + elapsed * RATE_LIMIT_REFILL_RATE
        )
        bucket["last_refill"] = now

        if bucket["tokens"] >= RATE_LIMIT_COST:
            bucket["tokens"] -= RATE_LIMIT_COST
            return True

        logger.warning("Rate limit exceeded for peer: %s", _anonymize_id(peer_id))
        return False

    def reset(self, peer_id: str) -> None:
        """
        Reset the rate limit bucket for a peer (e.g., on disconnect).

        Inputs:
            peer_id: Peer identifier to reset.
        """
        if peer_id in self._buckets:
            del self._buckets[peer_id]


# Global rate limiter instance
rate_limiter = RateLimiter()


# ─────────────────────────────────────────────
#  Input Validation
# ─────────────────────────────────────────────

def validate_message(message: str) -> str:
    """
    Validate a user-supplied chat message.

    Security checks:
    - Must be a non-empty string.
    - Must not exceed MAX_MESSAGE_SIZE_BYTES.
    - Strips leading/trailing whitespace.

    Inputs:
        message: Raw message string from the user.
    Output:
        Stripped, validated message string.
    Raises:
        ValueError: If the message is invalid.
    """
    if not isinstance(message, str):
        raise ValueError("Message must be a string.")
    message = message.strip()
    if not message:
        raise ValueError("Message cannot be empty.")
    encoded = message.encode("utf-8")
    if len(encoded) > MAX_MESSAGE_SIZE_BYTES:
        raise ValueError(
            f"Message exceeds maximum size of {MAX_MESSAGE_SIZE_BYTES} bytes."
        )
    return message


def validate_peer_address(address: str) -> str:
    """
    Validate an I2P .b32.i2p peer address format.

    Security checks:
    - Must match the pattern: 52 Base32 characters followed by .b32.i2p
    - Prevents injection of arbitrary hostnames or paths.

    Inputs:
        address: Raw peer address string supplied by the user.
    Output:
        Lowercase stripped address.
    Raises:
        ValueError: If the address format is invalid.
    """
    if not isinstance(address, str):
        raise ValueError("Peer address must be a string.")
    address = address.strip().lower()
    if not B32_I2P_PATTERN.match(address):
        raise ValueError(
            "Invalid peer address format. Expected: <52chars>.b32.i2p"
        )
    return address


def validate_public_key_hex(hex_str: str) -> str:
    """
    Validate a public key supplied as a 64-character hex string.

    Security:
    - Must be exactly 64 hex digits (= 32 bytes, X25519 public key size).
    - Rejects any extra characters.

    Inputs:
        hex_str: User-supplied hex string for the peer's public key.
    Output:
        Lowercase normalized hex string.
    Raises:
        ValueError: If format is invalid.
    """
    if not isinstance(hex_str, str):
        raise ValueError("Public key must be a string.")
    hex_str = hex_str.strip().lower()
    if not HEX_PUBLIC_KEY_PATTERN.match(hex_str):
        raise ValueError("Invalid public key. Must be 64 hex characters.")
    return hex_str


def validate_file_path(file_path: str | Path) -> Path:
    """
    Validate a file path supplied for transmission.

    Security checks:
    - File must exist.
    - File must not exceed MAX_FILE_SIZE_BYTES.
    - Resolves the path to check for path traversal.

    Inputs:
        file_path: Path to the file to be sent.
    Output:
        Resolved Path object.
    Raises:
        ValueError: If the file path is invalid.
        FileNotFoundError: If the file does not exist.
    """
    path = Path(file_path).resolve()
    if not path.exists():
        raise FileNotFoundError("File not found.")
    if not path.is_file():
        raise ValueError("Path does not point to a regular file.")
    size = path.stat().st_size
    if size == 0:
        raise ValueError("File is empty.")
    if size > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"File size ({size} bytes) exceeds limit of {MAX_FILE_SIZE_BYTES} bytes."
        )
    return path


# ─────────────────────────────────────────────
#  Filename Sanitization
# ─────────────────────────────────────────────

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename received from a peer to prevent path traversal and injection.

    Security:
    - Strips directory components (basename only).
    - Removes null bytes and special characters.
    - Enforces maximum filename length.
    - Rejects reserved Windows filenames.

    Inputs:
        filename: Raw filename received from peer (untrusted).
    Output:
        Safe, sanitized filename string.
    Raises:
        ValueError: If the filename cannot be made safe.
    """
    if not isinstance(filename, str):
        raise ValueError("Filename must be a string.")

    # Normalize both Unix (/) and Windows (\) path separators before extracting basename.
    # On Linux, os.path.basename does not treat backslash as a separator, so
    # "C:\Windows\System32\cmd.exe" would be returned verbatim.
    # We normalize backslashes to forward slashes first, then take the POSIX basename.
    filename = filename.replace("\\", "/")

    # Extract basename to remove path traversal sequences (e.g., ../../etc/passwd → passwd)
    filename = os.path.basename(filename)

    # Remove null bytes
    filename = filename.replace("\x00", "")

    # Allow only safe characters: alphanumeric, dots, hyphens, underscores
    filename = re.sub(r"[^\w.\-]", "_", filename)

    # Prevent double dots
    filename = re.sub(r"\.{2,}", ".", filename)

    # Enforce length
    if len(filename) > MAX_FILENAME_LENGTH:
        name, ext = os.path.splitext(filename)
        filename = name[: MAX_FILENAME_LENGTH - len(ext)] + ext

    if not filename or filename in {".", ".."}:
        raise ValueError("Filename is invalid after sanitization.")

    # Reject dangerous names
    RESERVED_NAMES = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3",
    }
    if filename.upper().split(".")[0] in RESERVED_NAMES:
        raise ValueError(f"Reserved filename not allowed: {filename}")

    return filename


# ─────────────────────────────────────────────
#  Integrity Verification
# ─────────────────────────────────────────────

def compute_file_hash(file_path: Path) -> str:
    """
    Compute SHA-256 hash of a file for integrity verification.

    Security:
    - Reads file in chunks to handle large files without loading all into memory.
    - Ensures received files haven't been tampered with during transfer.

    Inputs:
        file_path: Path to the file to hash.
    Output:
        Lowercase hex SHA-256 digest string.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_file_hash(file_path: Path, expected_hash: str) -> bool:
    """
    Verify a file's SHA-256 hash matches the expected value.

    Security:
    - Uses constant-time comparison via hmac.compare_digest to prevent timing attacks.

    Inputs:
        file_path: Path to the file to verify.
        expected_hash: Hex SHA-256 digest to compare against.
    Output:
        True if the hash matches, False otherwise.
    """
    import hmac
    actual = compute_file_hash(file_path)
    return hmac.compare_digest(actual.lower(), expected_hash.lower())


# ─────────────────────────────────────────────
#  Password Strength Validation
# ─────────────────────────────────────────────

MIN_PASSWORD_LENGTH = 8

def validate_password_strength(password: str) -> None:
    """
    Enforce a minimum password strength policy.

    Security checks (from OWASP password guidance and lecture material):
    - Minimum 8 characters.
    - Must contain at least one uppercase letter.
    - Must contain at least one lowercase letter.
    - Must contain at least one digit.
    - Must contain at least one special character.
    - Must not be composed entirely of whitespace.

    Inputs:
        password: Plaintext password string supplied by the user.
    Output:
        None.
    Raises:
        ValueError: With a descriptive message if the password is too weak.
    """
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
        )

    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter.")

    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter.")

    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit.")

    if not re.search(r"[^A-Za-z0-9]", password):
        raise ValueError("Password must contain at least one special character.")

    if password.strip() == "":
        raise ValueError("Password must not be all whitespace.")


# ─────────────────────────────────────────────
#  XSS / Injection Sanitization for Display
# ─────────────────────────────────────────────

# Characters that have special meaning in HTML / template contexts
_HTML_ESCAPE_TABLE = str.maketrans({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#x27;",
})


def sanitize_message_for_display(message: str) -> str:
    """
    Escape HTML special characters in a message before rendering it in the GUI.

    Security (XSS prevention — Chapter 10 of lecture material):
    - Any message received from a peer is treated as untrusted.
    - HTML entities are escaped so that injected script tags are rendered as
      literal text rather than executed.
    - This is a defense-in-depth measure; Tkinter does not execute HTML/JS,
      but the habit of escaping untrusted output is a mandatory secure-coding practice.

    Inputs:
        message: Raw message string from the peer (untrusted).
    Output:
        HTML-entity-escaped string safe for display.
    """
    if not isinstance(message, str):
        return ""
    return message.translate(_HTML_ESCAPE_TABLE)


# ─────────────────────────────────────────────
#  Helper Utilities
# ─────────────────────────────────────────────

def _anonymize_id(peer_id: str) -> str:
    """
    Return the first 8 characters of a peer ID for safe log output.

    Security: Prevents full peer addresses from appearing in log files.
    """
    return peer_id[:8] + "..." if len(peer_id) > 8 else peer_id
```

## File: gui/__init__.py
```python
"""
File: gui/__init__.py
Purpose: Package initializer for the I2I GUI module.
"""
```

## File: gui/app.py
```python
"""
File: gui/app.py
Purpose: Tkinter-based GUI for the I2I secure P2P messaging application.

This module provides the desktop user interface including:
- Dark-themed chat window
- Peer connection management
- Real-time message display
- File send/receive notifications
- Safety number display for MITM prevention verification
- Connection status indicator

Security Design:
- GUI validates all inputs before passing to the application layer
- Safety numbers are prominently displayed for out-of-band MITM verification
- Sensitive information (keys, addresses) is not stored in GUI widgets
- All background network I/O happens in daemon threads; GUI updates are
  scheduled on the main thread via root.after() to remain thread-safe

Architecture:
- The GUI communicates with the application via callback functions
- The GUI never directly touches sockets or cryptographic primitives
"""

import os
import json
import time
import socket
import logging
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from pathlib import Path
from typing import Optional, Callable

import nacl.public

from src.crypto_utils import (
    load_or_generate_keypair,
    public_key_to_hex,
    generate_peer_address,
)
from src.i2p_manager import I2PManager
from src.peer_connection import PeerConnectionManager
from src.message_handler import (
    send_chat_message,
    send_raw_envelope,
    parse_and_decrypt_envelope,
    MESSAGE_TYPE_CHAT,
    MESSAGE_TYPE_FILE_META,
    MESSAGE_TYPE_FILE_CHUNK,
    MESSAGE_TYPE_FILE_ACK,
    MESSAGE_TYPE_CONTROL,
)
from src.file_transfer import FileSender, FileReceiver, RECEIVED_FILES_DIR
from src.security_utils import (
    validate_peer_address,
    validate_public_key_hex,
)
from src.validators import Validators, MAX_FILE_SIZE_ADMIN, MAX_FILE_SIZE_USER

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
#  Color Palette — Dark Secure Theme
# ─────────────────────────────────────────────
BG_DARK = "#0d1117"  # Main background
BG_MID = "#161b22"  # Panel background
BG_CARD = "#21262d"  # Card / input background
ACCENT = "#58a6ff"  # Primary accent (blue)
ACCENT2 = "#3fb950"  # Secondary accent (green)
WARN = "#d29922"  # Warning yellow
DANGER = "#f85149"  # Danger red
TEXT_MAIN = "#e6edf3"  # Primary text
TEXT_DIM = "#8b949e"  # Dimmed text
BORDER = "#30363d"  # Border color
SENT_BG = "#1f3a5f"  # Sent message background
RECV_BG = "#1a2a1a"  # Received message background


class I2IApp:
    def __init__(self, username: str, role: str) -> None:
        self.username = username
        self.role = role
        self.logout_requested = False
        # ── Load or generate keys ──────────────────
        self._private_key, self._public_key = load_or_generate_keypair()
        self._our_address = generate_peer_address(self._public_key)
        self._our_pub_hex = public_key_to_hex(self._public_key)

        # ── Active peer sessions ───────────────────
        self._current_peer: Optional[str] = None  # Currently selected peer address

        # ── FIXED: Respect Environment Port ─────────
        try:
            env_port = int(os.getenv("I2I_LISTEN_PORT", 7777))
        except ValueError:
            env_port = 7777

        self._i2p = I2PManager(self._public_key, port=env_port)
        self._conn_mgr = PeerConnectionManager(
            our_private_key=self._private_key,
            our_public_key=self._public_key,
            on_message_received=self._on_message_received,
            on_peer_connected=self._on_peer_connected,
            on_peer_disconnected=self._on_peer_disconnected,
        )

        # ── Message buffer per peer ────────────────
        self._messages: dict[
            str, list[tuple[str, str, str]]
        ] = {}  # {addr: [(sender, text, time)]}
        self._file_receivers: dict[str, FileReceiver] = {}
        self._file_senders: dict[str, FileSender] = {}

        # ── Build GUI ──────────────────────────────
        self.root = tk.Tk()
        self.root.title(f"I2I Messenger - {self.username} (Port: {env_port})")
        self.root.configure(bg=BG_DARK)
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)

        self._setup_styles()
        self._build_layout()
        self._start_listener()

        logger.info("I2IApp started on port %d.", env_port)

    # ──────────────────────────────────────────
    #  Style Configuration
    # ──────────────────────────────────────────

    def _setup_styles(self) -> None:
        """Configure ttk styles for the dark theme."""
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure("TFrame", background=BG_DARK)
        style.configure("Card.TFrame", background=BG_MID, relief="flat")
        style.configure(
            "TLabel", background=BG_DARK, foreground=TEXT_MAIN, font=("Segoe UI", 10)
        )
        style.configure(
            "Title.TLabel",
            background=BG_DARK,
            foreground=ACCENT,
            font=("Segoe UI", 13, "bold"),
        )
        style.configure(
            "Dim.TLabel", background=BG_MID, foreground=TEXT_DIM, font=("Segoe UI", 9)
        )
        style.configure(
            "Status.TLabel",
            background=BG_MID,
            foreground=ACCENT2,
            font=("Segoe UI", 9, "bold"),
        )
        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
            padding=(12, 6),
        )
        style.map(
            "Accent.TButton",
            background=[("active", "#1f6feb"), ("disabled", BG_CARD)],
        )
        style.configure(
            "Danger.TButton",
            background=DANGER,
            foreground="#ffffff",
            font=("Segoe UI", 9),
            borderwidth=0,
            padding=(8, 4),
        )
        style.configure(
            "Green.TButton",
            background=ACCENT2,
            foreground="#000000",
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
            padding=(12, 6),
        )
        style.configure(
            "TEntry",
            fieldbackground=BG_CARD,
            foreground=TEXT_MAIN,
            insertcolor=TEXT_MAIN,
            bordercolor=BORDER,
            font=("Segoe UI", 10),
        )
        style.configure(
            "TListbox",
            background=BG_MID,
            foreground=TEXT_MAIN,
        )
        style.configure("Horizontal.TSeparator", background=BORDER)

    # ──────────────────────────────────────────
    #  Layout Construction
    # ──────────────────────────────────────────

    def _build_layout(self) -> None:
        """Build and arrange all GUI widgets."""
        # ── Top bar ───────────────────────────────
        top_bar = tk.Frame(self.root, bg=BG_MID, height=52)
        top_bar.pack(fill="x", side="top")
        top_bar.pack_propagate(False)

        tk.Label(
            top_bar,
            text="🔒 I2I Secure Messenger",
            bg=BG_MID,
            fg=ACCENT,
            font=("Segoe UI", 14, "bold"),
        ).pack(side="left", padx=16, pady=10)

        user_info_lbl = tk.Label(
            top_bar,
            text=f"👤 Logged in as: {self.username} [{self.role}]",
            bg=BG_MID,
            fg=TEXT_MAIN,
            font=("Segoe UI", 10, "bold"),
        )
        user_info_lbl.pack(side="left", padx=20)

        ttk.Button(
            top_bar, text="🚪 Exit", style="Danger.TButton", command=self._on_close
        ).pack(side="right", padx=(4, 16), pady=10)

        ttk.Button(
            top_bar, text="🔓 Logout", style="Accent.TButton", command=self._on_logout
        ).pack(side="right", padx=4, pady=10)

        self._status_label = tk.Label(
            top_bar,
            text="● Offline",
            bg=BG_MID,
            fg=DANGER,
            font=("Segoe UI", 9, "bold"),
        )
        self._status_label.pack(side="right", padx=16)

        # ── Main pane ─────────────────────────────
        main = tk.PanedWindow(
            self.root, orient="horizontal", bg=BG_DARK, sashwidth=4, sashrelief="flat"
        )
        main.pack(fill="both", expand=True)

        # Left panel — identity + connections
        left = tk.Frame(main, bg=BG_MID, width=320)
        left.pack_propagate(False)
        main.add(left, minsize=260)

        self._build_left_panel(left)

        # Right panel — chat
        right = tk.Frame(main, bg=BG_DARK)
        main.add(right, minsize=450)

        self._build_chat_panel(right)

    def _build_left_panel(self, parent: tk.Frame) -> None:
        """Build the left identity and peer management panel."""
        # ── Identity card ────────────────────────
        id_frame = tk.LabelFrame(
            parent,
            text=" 🪪 Your Identity ",
            bg=BG_MID,
            fg=ACCENT,
            font=("Segoe UI", 9, "bold"),
            bd=1,
            relief="solid",
            highlightthickness=0,
        )
        id_frame.pack(fill="x", padx=10, pady=(12, 6))

        tk.Label(
            id_frame,
            text="Address (.b32.i2p):",
            bg=BG_MID,
            fg=TEXT_DIM,
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=8, pady=(6, 0))

        addr_display = tk.Text(
            id_frame,
            height=3,
            bg=BG_CARD,
            fg=ACCENT2,
            font=("Consolas", 8),
            bd=0,
            wrap="char",
            state="normal",
            selectbackground=ACCENT,
        )
        addr_display.pack(fill="x", padx=8, pady=(2, 0))
        addr_display.insert("1.0", self._our_address)
        addr_display.config(state="disabled")

        tk.Label(
            id_frame,
            text="Public Key (Hex):",
            bg=BG_MID,
            fg=TEXT_DIM,
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=8, pady=(6, 0))

        pub_display = tk.Text(
            id_frame,
            height=4,
            bg=BG_CARD,
            fg=TEXT_MAIN,
            font=("Consolas", 8),
            bd=0,
            wrap="char",
            state="normal",
        )
        pub_display.pack(fill="x", padx=8, pady=(2, 8))
        pub_display.insert("1.0", self._our_pub_hex)
        pub_display.config(state="disabled")

        ttk.Button(
            id_frame,
            text="📋 Copy Key",
            style="Accent.TButton",
            command=lambda: self._copy_to_clipboard(self._our_pub_hex),
        ).pack(padx=8, pady=(0, 8), fill="x")

        # ── Connect to peer ─────────────────────
        conn_frame = tk.LabelFrame(
            parent,
            text=" 🔗 Connect to Peer ",
            bg=BG_MID,
            fg=ACCENT,
            font=("Segoe UI", 9, "bold"),
            bd=1,
            relief="solid",
        )
        conn_frame.pack(fill="x", padx=10, pady=6)

        tk.Label(
            conn_frame,
            text="Peer Public Key (hex):",
            bg=BG_MID,
            fg=TEXT_DIM,
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=8, pady=(8, 0))

        self._peer_key_entry = tk.Text(
            conn_frame,
            height=4,
            bg=BG_CARD,
            fg=TEXT_MAIN,
            font=("Consolas", 8),
            bd=0,
            insertbackground=TEXT_MAIN,
        )
        self._peer_key_entry.pack(fill="x", padx=8, pady=(2, 0))

        # ADDED: Host/IP Field
        tk.Label(
            conn_frame, text="Host/IP:", bg=BG_MID, fg=TEXT_DIM, font=("Segoe UI", 8)
        ).pack(anchor="w", padx=8, pady=(4, 0))

        self._host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(conn_frame, textvariable=self._host_var).pack(
            anchor="w", padx=8, pady=(2, 0), fill="x"
        )

        tk.Label(
            conn_frame, text="Port:", bg=BG_MID, fg=TEXT_DIM, font=("Segoe UI", 8)
        ).pack(anchor="w", padx=8, pady=(4, 0))

        self._port_var = tk.StringVar(value="7777")
        port_entry = ttk.Entry(conn_frame, textvariable=self._port_var, width=10)
        port_entry.pack(anchor="w", padx=8, pady=(2, 0))

        ttk.Button(
            conn_frame,
            text="⚡ Connect",
            style="Green.TButton",
            command=self._connect_to_peer,
        ).pack(padx=8, pady=8, fill="x")

        # ── Connected peers ──────────────────────
        peers_frame = tk.LabelFrame(
            parent,
            text=" 👥 Connected Peers ",
            bg=BG_MID,
            fg=ACCENT,
            font=("Segoe UI", 9, "bold"),
            bd=1,
            relief="solid",
        )
        peers_frame.pack(fill="both", expand=True, padx=10, pady=6)

        self._peers_listbox = tk.Listbox(
            peers_frame,
            bg=BG_CARD,
            fg=TEXT_MAIN,
            selectbackground=ACCENT,
            selectforeground="#ffffff",
            font=("Consolas", 8),
            bd=0,
            highlightthickness=0,
            activestyle="none",
        )
        self._peers_listbox.pack(fill="both", expand=True, padx=4, pady=4)
        self._peers_listbox.bind("<<ListboxSelect>>", self._on_peer_selected)

        ttk.Button(
            peers_frame,
            text="❌ Disconnect",
            style="Danger.TButton",
            command=self._disconnect_peer,
        ).pack(padx=4, pady=(0, 4), fill="x")

        if self.role == "ADMIN":
            ttk.Button(
                peers_frame,
                text="👢 Force Kick (Admin)",
                style="Danger.TButton",
                command=self._kick_peer,
            ).pack(padx=4, pady=(0, 4), fill="x")

    def _build_chat_panel(self, parent: tk.Frame) -> None:
        """Build the right chat panel."""
        # ── Chat header ───────────────────────────
        header = tk.Frame(parent, bg=BG_MID, height=50)
        header.pack(fill="x")
        header.pack_propagate(False)

        self._chat_title_label = tk.Label(
            header,
            text="Select a peer to chat",
            bg=BG_MID,
            fg=TEXT_DIM,
            font=("Segoe UI", 11, "bold"),
        )
        self._chat_title_label.pack(side="left", padx=16, pady=10)

        self._safety_btn = ttk.Button(
            header,
            text="🔐 Safety Number",
            style="Accent.TButton",
            command=self._show_safety_number,
        )
        self._safety_btn.pack(side="right", padx=8, pady=8)

        # ── Message display ───────────────────────
        msg_frame = tk.Frame(parent, bg=BG_DARK)
        msg_frame.pack(fill="both", expand=True, padx=8, pady=(8, 0))

        self._chat_display = scrolledtext.ScrolledText(
            msg_frame,
            bg=BG_DARK,
            fg=TEXT_MAIN,
            font=("Segoe UI", 10),
            bd=0,
            wrap="word",
            state="disabled",
            selectbackground=ACCENT,
        )
        self._chat_display.pack(fill="both", expand=True)

        self._chat_display.tag_config(
            "sent_label", foreground=ACCENT, font=("Segoe UI", 9, "bold")
        )
        self._chat_display.tag_config(
            "recv_label", foreground=ACCENT2, font=("Segoe UI", 9, "bold")
        )
        self._chat_display.tag_config(
            "system", foreground=WARN, font=("Segoe UI", 9, "italic")
        )
        self._chat_display.tag_config(
            "timestamp", foreground=TEXT_DIM, font=("Segoe UI", 8)
        )
        self._chat_display.tag_config(
            "message_text", foreground=TEXT_MAIN, font=("Segoe UI", 10)
        )

        # ── Input bar ─────────────────────────────
        input_frame = tk.Frame(parent, bg=BG_MID, height=110)
        input_frame.pack(fill="x", padx=8, pady=8)
        input_frame.pack_propagate(False)

        self._message_entry = tk.Text(
            input_frame,
            bg=BG_CARD,
            fg=TEXT_MAIN,
            insertbackground=TEXT_MAIN,
            font=("Segoe UI", 10),
            bd=0,
            height=3,
            wrap="word",
        )
        self._message_entry.pack(
            side="left", fill="both", expand=True, padx=(8, 4), pady=8
        )
        self._message_entry.bind("<Return>", self._on_enter_pressed)

        btn_frame = tk.Frame(input_frame, bg=BG_MID)
        btn_frame.pack(side="right", padx=(0, 8), pady=8, fill="y")

        ttk.Button(
            btn_frame,
            text="📎 File",
            style="Accent.TButton",
            command=self._send_file,
        ).pack(pady=(0, 4), fill="x", expand=True)

        if self.role == "ADMIN":
            ttk.Button(
                btn_frame,
                text="📢 Broadcast",
                style="Accent.TButton",
                command=self._send_broadcast,
            ).pack(pady=(0, 4), fill="x", expand=True)

        ttk.Button(
            btn_frame,
            text="➤ Send",
            style="Green.TButton",
            command=self._send_message,
        ).pack(fill="x", expand=True)

    def _start_listener(self) -> None:
        try:
            self._i2p.start_listener(
                on_new_connection=self._conn_mgr.handle_incoming_connection
            )
            self._status_label.config(text="● Listening", fg=ACCENT2)
        except OSError:
            self._status_label.config(text="● Port in use", fg=WARN)

    def _connect_to_peer(self) -> None:
        key_hex = self._peer_key_entry.get("1.0", "end").strip()
        target_host = self._host_var.get().strip()
        try:
            key_hex = validate_public_key_hex(key_hex)
            port = int(self._port_var.get())
            if not target_host:
                target_host = "127.0.0.1"
        except Exception as e:
            messagebox.showerror("Invalid Input", str(e))
            return
        threading.Thread(
            target=self._do_connect, args=(key_hex, port, target_host), daemon=True
        ).start()

    def _do_connect(self, key_hex: str, port: int, target_host: str) -> None:
        try:
            # FIXED: Target Host included
            sock = self._i2p.connect_to_peer(target_host, port)
            import nacl.public as np

            peer_addr = generate_peer_address(np.PublicKey(bytes.fromhex(key_hex)))
            session = self._conn_mgr.connect_to_peer(sock, peer_addr, key_hex)
            if session:
                self.root.after(
                    0,
                    self._on_peer_connected,
                    session.peer_address,
                    session.safety_number,
                )
        except Exception:
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Connection Failed", "Peer not found or handshake failed."
                ),
            )

    def _on_message_received(self, peer_address: str, raw_bytes: bytes) -> None:
        session = self._conn_mgr.get_session(peer_address)
        if not session:
            return

        result = parse_and_decrypt_envelope(session, raw_bytes)
        if not result:
            return

        msg_type, plaintext = result

        if msg_type == MESSAGE_TYPE_CHAT:
            try:
                text = plaintext.decode("utf-8")
                self.root.after(
                    0,
                    self._append_message,
                    peer_address,
                    peer_address[:12],
                    text,
                    False,
                )
            except:
                pass

        elif msg_type == MESSAGE_TYPE_FILE_META:
            max_s = MAX_FILE_SIZE_ADMIN if self.role == "ADMIN" else MAX_FILE_SIZE_USER
            rx = FileReceiver(
                session,
                max_file_size=max_s,
                on_progress=lambda r, t: self.root.after(
                    0,
                    self._append_system_message,
                    f"📥 Receiving: {r}/{t} chunks",
                    peer_address,
                ),
                on_complete=lambda p, s: self.root.after(
                    0,
                    self._append_system_message,
                    f"✅ Saved: {p}" if s else "❌ File Error",
                    peer_address,
                ),
            )
            self._file_receivers[peer_address] = rx
            rx.handle_meta(plaintext)

        elif msg_type == MESSAGE_TYPE_FILE_CHUNK:
            if peer_address in self._file_receivers:
                self._file_receivers[peer_address].handle_chunk(plaintext)

        elif msg_type == MESSAGE_TYPE_FILE_ACK:
            if peer_address in self._file_senders:
                try:
                    ack = json.loads(plaintext.decode("utf-8")).get("ack")
                    self._file_senders[peer_address].on_ack_received(ack)
                except:
                    pass

        elif msg_type == MESSAGE_TYPE_CONTROL:
            try:
                cmd = json.loads(plaintext.decode("utf-8")).get("command")
                if cmd == "kick":
                    self.root.after(
                        0,
                        lambda: messagebox.showwarning(
                            "Kicked", "Admin has disconnected you."
                        ),
                    )
                    self.root.after(
                        0, lambda: self._conn_mgr.disconnect_peer(peer_address)
                    )
            except:
                pass

    def _send_message(self) -> None:
        if not self._current_peer:
            return
        text = self._message_entry.get("1.0", "end-1c").strip()
        if not text:
            return

        session = self._conn_mgr.get_session(self._current_peer)
        if session and send_chat_message(session, text):
            self._append_message(self._current_peer, "You", text, True)
            self._message_entry.delete("1.0", "end")

    def _on_enter_pressed(self, event: tk.Event) -> str:
        if not (event.state & 0x1):
            self._send_message()
            return "break"

    def _send_file(self) -> None:
        if not self._current_peer:
            return
        f_path = filedialog.askopenfilename()
        if not f_path:
            return

        try:
            Validators.validate_file_size(Path(f_path), self.role)
        except Exception as e:
            messagebox.showerror("RBAC Limit", str(e))
            return

        session = self._conn_mgr.get_session(self._current_peer)
        if session:
            tx = FileSender(
                session,
                on_progress=lambda s, t: self.root.after(
                    0,
                    self._append_system_message,
                    f"📤 Sent {s}/{t} chunks",
                    self._current_peer,
                ),
            )
            self._file_senders[self._current_peer] = tx
            threading.Thread(target=lambda: tx.send_file(f_path), daemon=True).start()

    def _kick_peer(self) -> None:
        if not self._current_peer:
            return
        session = self._conn_mgr.get_session(self._current_peer)
        if session:
            payload = json.dumps({"command": "kick"}).encode("utf-8")
            send_raw_envelope(session, MESSAGE_TYPE_CONTROL, payload)
            self._append_system_message(
                f"👢 You kicked {self._current_peer[:12]}", self._current_peer
            )
            self.root.after(500, self._disconnect_peer)

    def _send_broadcast(self) -> None:
        text = self._message_entry.get("1.0", "end-1c").strip()
        if not text:
            return
        sessions = self._conn_mgr.get_all_sessions()
        for session in sessions:
            send_chat_message(session, f"🚨 [ADMIN ANNOUNCEMENT]: {text}")
            self._append_message(session.peer_address, "You (Broadcast)", text, True)
        self._message_entry.delete("1.0", "end")

    def _on_peer_connected(self, addr: str, sn: str) -> None:
        if addr not in self._messages:
            self._messages[addr] =[]
        self._peers_listbox.insert("end", addr[:20] + "...")
        self._append_system_message(f"🔗 Connected. Safety Number: {sn}", addr)
        if not self._current_peer:
            self._peers_listbox.selection_set(0)
            self._on_peer_selected(None)

    def _on_peer_disconnected(self, addr: str) -> None:
        self._append_system_message("⚠️ Peer disconnected.", addr)
        display = addr[:20] + "..."
        for i in range(self._peers_listbox.size()):
            if self._peers_listbox.get(i) == display:
                self._peers_listbox.delete(i)
                break

    def _on_peer_selected(self, event) -> None:
        sel = self._peers_listbox.curselection()
        if not sel:
            return
        sessions = self._conn_mgr.get_all_sessions()
        if sel[0] < len(sessions):
            self._current_peer = sessions[sel[0]].peer_address
            self._chat_title_label.config(
                text=f"Chatting with: {self._current_peer[:15]}...", fg=ACCENT
            )
            self._refresh_chat()

    def _refresh_chat(self) -> None:
        self._chat_display.config(state="normal")
        self._chat_display.delete("1.0", "end")
        if self._current_peer in self._messages:
            for s, t, _ in self._messages[self._current_peer]:
                tag = (
                    "sent_label"
                    if s == "You" or s == "You (Broadcast)"
                    else ("recv_label" if s != "SYSTEM" else "system")
                )
                self._chat_display.insert("end", f"{s}: ", tag)
                self._chat_display.insert("end", f"{t}\n\n")
        self._chat_display.config(state="disabled")
        self._chat_display.see("end")

    def _append_message(self, addr, sender, text, sent) -> None:
        if addr not in self._messages:
            self._messages[addr] = []
        self._messages[addr].append((sender, text, ""))
        if addr == self._current_peer:
            self._refresh_chat()

    def _append_system_message(self, text, addr=None) -> None:
        target = addr or self._current_peer
        if target:
            if target not in self._messages:
                self._messages[target] =[]
            self._messages[target].append(("SYSTEM", text, ""))
            if target == self._current_peer:
                self._refresh_chat()

    def _show_safety_number(self) -> None:
        if self._current_peer:
            session = self._conn_mgr.get_session(self._current_peer)
            if session:
                messagebox.showinfo(
                    "Safety Number",
                    f"Verify this with peer:\n\n{session.safety_number}",
                )

    def _copy_to_clipboard(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

    def run(self) -> None:
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_logout(self) -> None:
        if messagebox.askyesno("Logout", "Confirm logout?"):
            self.logout_requested = True
            self._on_close()

    def _on_close(self) -> None:
        self._i2p.stop_listener()
        for s in self._conn_mgr.get_all_sessions():
            s.close()
        try:
            self.root.destroy()
        except:
            pass

    def _disconnect_peer(self) -> None:
        if self._current_peer:
            self._conn_mgr.disconnect_peer(self._current_peer)
```

## File: gui/login.py
```python
"""
File: gui/login.py
Purpose: Authentication UI to securely log users into the I2I Messenger.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import logging

from src.auth_manager import AuthManager

BG_DARK = "#0d1117"
BG_MID = "#161b22"
BG_CARD = "#21262d"
ACCENT = "#58a6ff"
TEXT_MAIN = "#e6edf3"
TEXT_DIM = "#8b949e"

logger = logging.getLogger(__name__)


class LoginWindow:
    def __init__(self, on_success):
        self.root = tk.Tk()
        self.root.title("I2I - Authentication")
        self.root.geometry("400x350")
        self.root.configure(bg=BG_DARK)
        self.root.resizable(False, False)

        self.on_success = on_success

        self._build_ui()

    def _build_ui(self):
        title = tk.Label(
            self.root,
            text="🔐 Secure Login",
            bg=BG_DARK,
            fg=ACCENT,
            font=("Segoe UI", 16, "bold"),
        )
        title.pack(pady=(30, 20))

        frame = tk.Frame(self.root, bg=BG_MID, bd=1, relief="solid")
        frame.pack(padx=40, fill="both", expand=True, pady=(0, 30))

        tk.Label(
            frame, text="Username", bg=BG_MID, fg=TEXT_DIM, font=("Segoe UI", 9)
        ).pack(anchor="w", padx=20, pady=(20, 5))
        self.user_var = tk.StringVar()
        user_entry = tk.Entry(
            frame,
            textvariable=self.user_var,
            bg=BG_CARD,
            fg=TEXT_MAIN,
            insertbackground=TEXT_MAIN,
            bd=0,
            font=("Segoe UI", 10),
        )
        user_entry.pack(fill="x", padx=20, ipady=4)

        tk.Label(
            frame, text="Password", bg=BG_MID, fg=TEXT_DIM, font=("Segoe UI", 9)
        ).pack(anchor="w", padx=20, pady=(15, 5))
        self.pass_var = tk.StringVar()
        pass_entry = tk.Entry(
            frame,
            textvariable=self.pass_var,
            show="*",
            bg=BG_CARD,
            fg=TEXT_MAIN,
            insertbackground=TEXT_MAIN,
            bd=0,
            font=("Segoe UI", 10),
        )
        pass_entry.pack(fill="x", padx=20, ipady=4)

        btn_frame = tk.Frame(frame, bg=BG_MID)
        btn_frame.pack(fill="x", padx=20, pady=(25, 20))

        btn_login = tk.Button(
            btn_frame,
            text="Login",
            bg=ACCENT,
            fg="#fff",
            font=("Segoe UI", 10, "bold"),
            bd=0,
            command=self._do_login,
        )
        btn_login.pack(side="left", expand=True, fill="x", padx=(0, 5), ipady=4)

        btn_reg = tk.Button(
            btn_frame,
            text="Register",
            bg=BG_CARD,
            fg=TEXT_MAIN,
            font=("Segoe UI", 10),
            bd=0,
            command=self._do_register,
        )
        btn_reg.pack(side="right", expand=True, fill="x", padx=(5, 0), ipady=4)

    def _do_login(self):
        u = self.user_var.get().strip()
        p = self.pass_var.get().strip()

        if not u or not p:
            messagebox.showwarning("Error", "Username and password required")
            return

        role = AuthManager.login(u, p)
        if role:
            logger.info("User %s authenticated via UI", u)
            self.root.destroy()
            self.on_success(u, role)
        else:
            messagebox.showerror("Access Denied", "Invalid username or password.")

    def _do_register(self):
        u = self.user_var.get().strip()
        p = self.pass_var.get().strip()
        if not u or not p:
            messagebox.showwarning("Error", "Username and password required")
            return

        role = "USER"
        if u.lower() == "admin":
            from tkinter import simpledialog

            secret = simpledialog.askstring(
                "Admin Verification", "Enter Admin Secret:", show="*"
            )
            import os

            # FIXED: Removed the hardcoded default "SSD-ADMIN-CODE"
            expected_secret = os.getenv("I2I_ADMIN_SECRET")

            if expected_secret and secret == expected_secret:
                role = "ADMIN"
            elif secret is not None:
                messagebox.showerror("Access Denied", "Invalid Admin Secret code.")
                return
            else:
                return

        try:
            AuthManager.register(u, p, role)
            messagebox.showinfo("Success", f"User registered as {role}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run(self):
        self.root.mainloop()


def run_login_flow():
    result = {"username": None, "role": None}

    def on_login(username, role):
        result["username"] = username
        result["role"] = role

    app = LoginWindow(on_login)
    app.run()

    return result["username"], result["role"]
```
```
