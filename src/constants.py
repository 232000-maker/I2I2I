"""
I2I2I Client Constants - Aligned with Crypto Domain
All constants now imported from onion_crypto to ensure consistency
"""

from src.onion_crypto import (
    # Packet sizes
    FRAME_SIZE,
    NONCE_SIZE,
    HEADER_SIZE,
    PAYLOAD_SIZE,
    PADDING_SIZE,
    
    # E2E encryption
    E2E_PLAINTEXT_SIZE,
    E2E_BLOCK_SIZE,
    E2E_SESSION_NOISE,
    
    # Opcodes
    Opcode,
)

# Network configuration
DIRECTORY_URL = "http://directory:5001"
RELAY_DELAY_MIN = 0.5
RELAY_DELAY_MAX = 2.0

# Timeouts & Retries
HANDSHAKE_TIMEOUT = 30
MAX_RETRIES = 3
FILE_BATCH_TIMEOUT = 120
BATCH_SIZE = 50
CHUNK_SIZE = 3563  # Max payload per file chunk
FLUSH_INTERVAL = 8

# Registration
LEASE_TTL = 30

# Connection States
STATE_IDLE = "IDLE"
STATE_AWAITING_CIRCUIT = "AWAITING_CIRCUIT"
STATE_AWAITING_ACK = "AWAITING_ACK"
STATE_SESSION_ACTIVE = "SESSION_ACTIVE"

# Decryption Modes (Bob's Dual State)
MODE_HANDSHAKE = "HANDSHAKE"
MODE_SESSION = "SESSION"