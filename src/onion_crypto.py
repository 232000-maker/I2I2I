# src/onion_crypto.py
"""
I2I2I Onion Crypto Module
=========================
Domain: Core Cryptography (Huzzi's Domain)

Pure mathematical and cryptographic black box.

CONTRACT:
  - Input : plaintext payload (str | bytes) + ordered routing path
  - Output: fully padded, encrypted 4096-byte bytearray

ZERO awareness of: sockets, queues, threading, or event loops.
CPU-bound synchronous cryptographic transformations only.

Specification Reference: plan_crypto.md + Masterplan.md v2.0 Final
"""

import os
import struct
import socket
import logging
from pathlib import Path
from typing import List, Tuple

import nacl.signing
import nacl.public
import nacl.secret
import nacl.utils

# ---------------------------------------------------------------------------
# Module Logger
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants — locked per Masterplan v2.0
# ---------------------------------------------------------------------------

# Wire frame layout
FRAME_SIZE       = 4096   # Total packet size (bytes)
NONCE_SIZE       = 24     # XSalsa20 nonce
HEADER_SIZE      = 64     # Routing header
PAYLOAD_SIZE     = 3632   # E2E block (handshake or session)
PADDING_SIZE     = 376    # Random noise tail
LAST_MILE_NOISE  = 464    # Noise appended after E2E block at last hop

# Header struct:  !B 32s 4s H 25s  = 1+32+4+2+25 = 64 bytes
HEADER_FORMAT    = "!B 32s 4s H 25s"
HEADER_FIELDS    = struct.calcsize(HEADER_FORMAT)       # must == 64
assert HEADER_FIELDS == HEADER_SIZE, (
    f"Header struct mismatch: {HEADER_FIELDS} != {HEADER_SIZE}"
)

# Onion layer offsets (3-hop, 112-byte step)
HOP3_OFFSET      = 24
HOP2_OFFSET      = 136
HOP1_OFFSET      = 248
OFFSET_STEP      = 112    # == PyNaCl SealedBox overhead (48) + inner nonce (24) + ... mathematical step

# SealedBox / SecretBox overhead
SEALEDBOX_OVERHEAD  = 48  # ephemeral pubkey (32) + Poly1305 tag (16)
SECRETBOX_OVERHEAD  = 40  # nonce (24) + Poly1305 tag (16)

# E2E block sizes (indistinguishability invariant)
E2E_PLAINTEXT_SIZE  = 3584
E2E_BLOCK_SIZE      = 3632   # 3584 + 48 (either path)
E2E_SESSION_NOISE   = 8      # random noise to equalize SecretBox overhead

# Opcode namespace
class Opcode:
    REG  = 0x00
    SYN  = 0x01
    CHAT = 0x02
    FILE = 0x03
    ACK  = 0x04
    PING = 0x05
    PONG = 0x06
    SACK = 0x07
    ERR  = 0xFF

# Key persistence paths (relative to CWD)
KEY_DIR       = Path("keys")
IDENTITY_KEY  = KEY_DIR / "identity.key"
IDENTITY_PUB  = KEY_DIR / "identity.pub"
X25519_PUB    = KEY_DIR / "x25519.pub"

# ---------------------------------------------------------------------------
# Key Hierarchy
# ---------------------------------------------------------------------------

class KeyHierarchy:
    """
    Manages exactly one Ed25519 signing key per node.
    X25519 keys are derived once at startup and cached.
    On-the-fly derivation is forbidden.
    """

    def __init__(self, key_dir: Path = KEY_DIR):
        self._key_dir = key_dir
        self._signing_key: nacl.signing.SigningKey | None = None
        self._verify_key:  nacl.signing.VerifyKey  | None = None
        self._x25519_private: nacl.public.PrivateKey | None = None
        self._x25519_public:  nacl.public.PublicKey  | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def initialise(self) -> None:
        """
        Derive once and cache.  Load from disk if keys already exist,
        otherwise generate fresh keys and persist.
        """
        self._key_dir.mkdir(parents=True, exist_ok=True)

        id_key_path = self._key_dir / "identity.key"
        id_pub_path = self._key_dir / "identity.pub"
        x_pub_path  = self._key_dir / "x25519.pub"

        if id_key_path.exists():
            logger.debug("Loading existing identity key from disk.")
            raw = id_key_path.read_bytes()
            self._signing_key = nacl.signing.SigningKey(raw)
        else:
            logger.debug("Generating new identity key.")
            self._signing_key = nacl.signing.SigningKey.generate()
            id_key_path.write_bytes(bytes(self._signing_key))

        # Derive verify key
        self._verify_key = self._signing_key.verify_key

        # Persist public identity key
        if not id_pub_path.exists():
            id_pub_path.write_bytes(bytes(self._verify_key))

        # Derive X25519 keys ONCE and cache — no on-the-fly derivation ever
        self._x25519_private = self._signing_key.to_curve25519_private_key()
        self._x25519_public  = self._x25519_private.public_key

        # Persist X25519 public key for directory registration
        if not x_pub_path.exists():
            x_pub_path.write_bytes(bytes(self._x25519_public))

        logger.info("KeyHierarchy initialised. X25519 pub: %s",
                    bytes(self._x25519_public).hex()[:16] + "...")

    # ------------------------------------------------------------------
    # Accessors — always use cached values
    # ------------------------------------------------------------------

    @property
    def signing_key(self) -> nacl.signing.SigningKey:
        self._assert_init()
        return self._signing_key

    @property
    def verify_key(self) -> nacl.signing.VerifyKey:
        self._assert_init()
        return self._verify_key

    @property
    def x25519_private(self) -> nacl.public.PrivateKey:
        self._assert_init()
        return self._x25519_private

    @property
    def x25519_public(self) -> nacl.public.PublicKey:
        self._assert_init()
        return self._x25519_public

    def sign(self, data: bytes) -> bytes:
        """Sign arbitrary bytes. Returns signed message."""
        self._assert_init()
        return bytes(self._signing_key.sign(data))

    # ------------------------------------------------------------------

    def _assert_init(self):
        if self._signing_key is None:
            raise RuntimeError("KeyHierarchy.initialise() must be called before use.")


# ---------------------------------------------------------------------------
# Header Packing / Unpacking
# ---------------------------------------------------------------------------

def pack_header(
    opcode: int,
    dest_pubkey: bytes,
    next_ip: str,
    next_port: int,
) -> bytes:
    """
    Pack a 64-byte routing header.

    struct format: !B 32s 4s H 25s
    """
    if len(dest_pubkey) != 32:
        raise ValueError(f"dest_pubkey must be 32 bytes, got {len(dest_pubkey)}")
    packed_ip = socket.inet_aton(next_ip)
    noise = nacl.utils.random(25)
    raw = struct.pack(HEADER_FORMAT, opcode, dest_pubkey, packed_ip, next_port, noise)
    assert len(raw) == HEADER_SIZE, f"Header packed to {len(raw)}, expected 64"
    return raw


def unpack_header(raw: bytes) -> dict:
    """
    Unpack a 64-byte routing header.
    Returns dict with keys: opcode, dest_pubkey, next_ip, next_port.
    """
    if len(raw) != HEADER_SIZE:
        raise ValueError(f"Header must be {HEADER_SIZE} bytes, got {len(raw)}")
    opcode, dest_pubkey, packed_ip, next_port, _ = struct.unpack(HEADER_FORMAT, raw)
    next_ip = socket.inet_ntoa(packed_ip)
    return {
        "opcode":      opcode,
        "dest_pubkey": dest_pubkey,
        "next_ip":     next_ip,
        "next_port":   next_port,
    }


# ---------------------------------------------------------------------------
# Wire Frame Assembly
# ---------------------------------------------------------------------------

def assemble_frame(nonce: bytes, header: bytes, payload: bytes) -> bytearray:
    """
    Assemble the final 4096-byte wire frame:
      [24B nonce][64B header][3632B payload][376B random padding]
    """
    assert len(nonce)   == NONCE_SIZE,   f"Nonce size: {len(nonce)}"
    assert len(header)  == HEADER_SIZE,  f"Header size: {len(header)}"
    assert len(payload) == PAYLOAD_SIZE, f"Payload size: {len(payload)}"

    padding = nacl.utils.random(PADDING_SIZE)
    frame   = bytearray(nonce + header + payload + padding)

    assert len(frame) == FRAME_SIZE, f"Frame size: {len(frame)}, expected {FRAME_SIZE}"
    return frame


def disassemble_frame(frame: bytes | bytearray) -> Tuple[bytes, bytes, bytes]:
    """
    Split a 4096-byte frame into (nonce, header, payload).
    Padding is discarded.
    """
    if len(frame) != FRAME_SIZE:
        raise ValueError(f"Frame must be {FRAME_SIZE} bytes, got {len(frame)}")
    nonce   = bytes(frame[:NONCE_SIZE])
    header  = bytes(frame[NONCE_SIZE : NONCE_SIZE + HEADER_SIZE])
    payload = bytes(frame[NONCE_SIZE + HEADER_SIZE : NONCE_SIZE + HEADER_SIZE + PAYLOAD_SIZE])
    return nonce, header, payload


# ---------------------------------------------------------------------------
# E2E Encryption (Last-Mile)
# ---------------------------------------------------------------------------

def encrypt_e2e_handshake(plaintext: bytes, dest_x25519_pub: nacl.public.PublicKey) -> bytes:
    """
    Handshake Phase (SealedBox): no prior shared secret required.

    Invariant: 3584B plaintext + 48B SealedBox overhead = 3632B
    """
    if len(plaintext) != E2E_PLAINTEXT_SIZE:
        raise ValueError(
            f"Handshake plaintext must be {E2E_PLAINTEXT_SIZE}B, got {len(plaintext)}"
        )
    box        = nacl.public.SealedBox(dest_x25519_pub)
    ciphertext = box.encrypt(plaintext)
    assert len(ciphertext) == E2E_BLOCK_SIZE, (
        f"Handshake E2E block: {len(ciphertext)}, expected {E2E_BLOCK_SIZE}"
    )
    return ciphertext


def decrypt_e2e_handshake(
    ciphertext: bytes,
    x25519_private: nacl.public.PrivateKey,
) -> bytes:
    """Decrypt a SealedBox E2E block. Returns 3584B plaintext."""
    box = nacl.public.SealedBox(x25519_private)
    return box.decrypt(ciphertext)


def encrypt_e2e_session(plaintext: bytes, shared_secret: bytes) -> bytes:
    """
    Session Phase (SecretBox): requires shared secret.

    Invariant: 3584B plaintext + 8B noise + 40B SecretBox overhead = 3632B
    The 8-byte noise equalises the overhead so Handshake and Session frames
    are mathematically indistinguishable in size.
    """
    if len(plaintext) != E2E_PLAINTEXT_SIZE:
        raise ValueError(
            f"Session plaintext must be {E2E_PLAINTEXT_SIZE}B, got {len(plaintext)}"
        )
    if len(shared_secret) != nacl.secret.SecretBox.KEY_SIZE:
        raise ValueError(
            f"Shared secret must be {nacl.secret.SecretBox.KEY_SIZE}B"
        )
    noise   = nacl.utils.random(E2E_SESSION_NOISE)
    padded  = noise + plaintext          # 8 + 3584 = 3592B
    box     = nacl.secret.SecretBox(shared_secret)
    # SecretBox.encrypt() prepends a 24B nonce → total = 24 + 16 + 3592 = 3632B
    ciphertext = box.encrypt(padded)
    assert len(ciphertext) == E2E_BLOCK_SIZE, (
        f"Session E2E block: {len(ciphertext)}, expected {E2E_BLOCK_SIZE}"
    )
    return ciphertext


def decrypt_e2e_session(ciphertext: bytes, shared_secret: bytes) -> bytes:
    """Decrypt a SecretBox E2E block. Returns 3584B plaintext (noise stripped)."""
    box     = nacl.secret.SecretBox(shared_secret)
    padded  = box.decrypt(ciphertext)   # 3592B (noise + plaintext)
    return padded[E2E_SESSION_NOISE:]   # strip 8B noise


# ---------------------------------------------------------------------------
# Last-Mile Delivery Block
# ---------------------------------------------------------------------------

def build_last_mile_block(e2e_block: bytes) -> bytes:
    """
    Build the 4096B last-mile delivery block handed to Bob:
      [3632B E2E block][464B random noise]
    """
    assert len(e2e_block) == E2E_BLOCK_SIZE, (
        f"E2E block must be {E2E_BLOCK_SIZE}B, got {len(e2e_block)}"
    )
    noise = nacl.utils.random(LAST_MILE_NOISE)
    block = bytearray(e2e_block + noise)
    assert len(block) == FRAME_SIZE
    return block


def extract_e2e_block(last_mile: bytes | bytearray) -> bytes:
    """Extract the 3632B E2E block from a 4096B last-mile delivery block."""
    if len(last_mile) != FRAME_SIZE:
        raise ValueError(f"Last-mile block must be {FRAME_SIZE}B, got {len(last_mile)}")
    return bytes(last_mile[:E2E_BLOCK_SIZE])


# ---------------------------------------------------------------------------
# Node descriptor (what the directory stores per node)
# ---------------------------------------------------------------------------

class NodeDescriptor:
    """
    Minimal node information used for circuit building.
    Mirrors the relay fields defined in the Masterplan:
      ed25519_pubkey, x25519_pubkey, ip, port
    """
    __slots__ = ("ed25519_pubkey", "x25519_pubkey", "ip", "port")

    def __init__(
        self,
        ed25519_pubkey: bytes,
        x25519_pubkey:  bytes,
        ip:   str,
        port: int,
    ):
        self.ed25519_pubkey = ed25519_pubkey
        self.x25519_pubkey  = x25519_pubkey
        self.ip   = ip
        self.port = port


# ---------------------------------------------------------------------------
# Onion Builder  (3-hop wrap)
# ---------------------------------------------------------------------------

def build_onion_packet(
    plaintext:    bytes | str,
    routing_path: List[NodeDescriptor],
    opcode:       int = Opcode.CHAT,
) -> bytearray:
    """
    Build a fully padded, 4096-byte onion-encrypted wire packet.

    Parameters
    ----------
    plaintext    : The application-layer payload (≤ E2E_PLAINTEXT_SIZE bytes).
                   Will be zero-padded on the right to exactly E2E_PLAINTEXT_SIZE.
    routing_path : Ordered list of exactly 3 NodeDescriptors [hop1, hop2, hop3/dest].
    opcode       : Wire opcode (default CHAT).

    Returns
    -------
    bytearray of exactly FRAME_SIZE (4096) bytes.

    Layer Math (SealedBox overhead = 48B, offset step = 112B):
      Hop 3 plaintext = 3648B  →  SealedBox  = 3696B
      Hop 2 plaintext = 3760B  →  SealedBox  = 3808B
      Hop 1 plaintext = 3872B  →  SealedBox  = 3920B
      Wire packet     = 4096B  (24B nonce + 64B header + 3920B inner + 88B padding)

    Offset anchors into Payload (3632B window):
      HOP3_OFFSET = 24  (start of hop-3 encrypted blob)
      HOP2_OFFSET = 136
      HOP1_OFFSET = 248
    """
    if len(routing_path) != 3:
        raise ValueError("routing_path must contain exactly 3 NodeDescriptors")

    # Encode plaintext
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    # Zero-pad payload to exactly E2E_PLAINTEXT_SIZE
    if len(plaintext) > E2E_PLAINTEXT_SIZE:
        raise ValueError(
            f"Plaintext too large: {len(plaintext)} > {E2E_PLAINTEXT_SIZE}"
        )
    plaintext = plaintext.ljust(E2E_PLAINTEXT_SIZE, b"\x00")

    hop1, hop2, hop3 = routing_path

    # ------------------------------------------------------------------
    # Layer 3 (innermost — destination / gateway)
    # ------------------------------------------------------------------
    # Plaintext for hop3 layer = 64B header_3 + 3584B payload = 3648B
    header_3 = pack_header(
        opcode,
        bytes(hop3.x25519_pubkey) if isinstance(hop3.x25519_pubkey, (bytes, bytearray)) else hop3.x25519_pubkey,
        hop3.ip,
        hop3.port,
    )
    inner_plain_3 = header_3 + plaintext           # 64 + 3584 = 3648B
    assert len(inner_plain_3) == 3648

    pub3 = nacl.public.PublicKey(
        hop3.x25519_pubkey if isinstance(hop3.x25519_pubkey, bytes) else bytes(hop3.x25519_pubkey)
    )
    layer3 = nacl.public.SealedBox(pub3).encrypt(inner_plain_3)  # 3648 + 48 = 3696B
    assert len(layer3) == 3696

    # ------------------------------------------------------------------
    # Layer 2 (middle relay)
    # ------------------------------------------------------------------
    # Plaintext for hop2 = 64B header_2 + pad + layer3
    # Total plaintext for hop2 = 3760B
    # Positioning: layer3 (3696B) is placed at offset HOP3_OFFSET=24 within
    # the 3696B payload window.  But we need the hop2 plaintext to be 3760B.
    # Layout: [64B header_2][24B zero-gap][3696B layer3] = 3784 — too big.
    #
    # Correct interpretation per spec:
    #   hop2 payload space = 3760B = 64B header + 3696B layer3
    #   The inner layer starts at offset HOP3_OFFSET=24 relative to the
    #   *payload field* (post-header), so:
    #   hop2 plaintext = [64B header_2][24B noise][3696B layer3 - 24B trim]
    #
    # Actually the cleanest reading: the 3760B plaintext is
    #   header (64B) + (inner at offset 24 from payload start) + padding
    # i.e. payload for hop2 = 3696B with layer3 starting at byte 24
    # => payload = random_24B + layer3 = 3720B... still off.
    #
    # Ground-truth math from spec:
    #   hop2 plaintext = 3760B  →  hop2 SealedBox = 3808B
    # So we need exactly 3760 bytes going into SealedBox for hop2.
    # That's:  64B header_2 + 3696B layer3 = 3760B ✓
    # The offset (HOP3_OFFSET=24) is where layer3 starts within the
    # *relay's payload view* (after the relay strips its own header).
    # The relay sees: [64B its own header][...rest as opaque bytes...]
    # and passes bytes starting at HOP3_OFFSET=24 into next SealedBox decrypt.
    # ------------------------------------------------------------------

    header_2 = pack_header(
        opcode,
        hop2.x25519_pubkey if isinstance(hop2.x25519_pubkey, bytes) else bytes(hop2.x25519_pubkey),
        hop2.ip,
        hop2.port,
    )
    inner_plain_2 = header_2 + layer3              # 64 + 3696 = 3760B
    assert len(inner_plain_2) == 3760

    pub2 = nacl.public.PublicKey(
        hop2.x25519_pubkey if isinstance(hop2.x25519_pubkey, bytes) else bytes(hop2.x25519_pubkey)
    )
    layer2 = nacl.public.SealedBox(pub2).encrypt(inner_plain_2)  # 3760 + 48 = 3808B
    assert len(layer2) == 3808

    # ------------------------------------------------------------------
    # Layer 1 (outermost — entry relay Alice connects to)
    # ------------------------------------------------------------------
    header_1 = pack_header(
        opcode,
        hop1.x25519_pubkey if isinstance(hop1.x25519_pubkey, bytes) else bytes(hop1.x25519_pubkey),
        hop1.ip,
        hop1.port,
    )
    inner_plain_1 = header_1 + layer2              # 64 + 3808 = 3872B
    assert len(inner_plain_1) == 3872

    pub1 = nacl.public.PublicKey(
        hop1.x25519_pubkey if isinstance(hop1.x25519_pubkey, bytes) else bytes(hop1.x25519_pubkey)
    )
    layer1 = nacl.public.SealedBox(pub1).encrypt(inner_plain_1)  # 3872 + 48 = 3920B
    assert len(layer1) == 3920

    # ------------------------------------------------------------------
    # Assemble 4096B wire frame
    # ------------------------------------------------------------------
    # Frame = [24B nonce][64B outer header][3920B layer1][88B padding]
    # But the spec defines Payload field as 3632B.
    # Resolution: the 3920B layer1 exceeds 3632B, so it cannot live inside
    # Payload alone.  The 4096B packet IS the nonce+header+onion+padding,
    # where the onion expands across payload+some-of-padding.
    # The relay's job is: decrypt layer1 using its private key, revealing
    # header_next + inner_cipher; re-pad to 4096B; forward.
    # Here we assemble the raw wire bytes as one contiguous 4096B block.

    nonce   = nacl.utils.random(NONCE_SIZE)          # 24B frame nonce (anti-replay)
    outer_h = pack_header(
        opcode,
        hop1.x25519_pubkey if isinstance(hop1.x25519_pubkey, bytes) else bytes(hop1.x25519_pubkey),
        hop1.ip,
        hop1.port,
    )

    # Total so far: 24 + 64 + 3920 = 4008B  → 88B padding to reach 4096B
    tail_padding_size = FRAME_SIZE - NONCE_SIZE - HEADER_SIZE - len(layer1)
    assert tail_padding_size >= 0, f"Onion too large: {tail_padding_size}"
    tail_padding = nacl.utils.random(tail_padding_size)

    frame = bytearray(nonce + outer_h + layer1 + tail_padding)
    assert len(frame) == FRAME_SIZE, (
        f"Final frame size {len(frame)}, expected {FRAME_SIZE}"
    )
    return frame


# ---------------------------------------------------------------------------
# Trial Peel  (relay-side — peel one onion layer)
# ---------------------------------------------------------------------------

def trial_peel(
    frame:       bytes | bytearray,
    key_hier:    KeyHierarchy,
) -> Tuple[dict, bytes]:
    """
    Attempt to peel one onion layer from a 4096B frame.

    Returns (header_dict, inner_bytes) where inner_bytes is the
    decrypted payload starting just after this relay's header.

    Raises nacl.exceptions.CryptoError if decryption fails
    (packet not destined for this node).
    """
    if len(frame) != FRAME_SIZE:
        raise ValueError(f"Frame must be {FRAME_SIZE}B")

    # layer1 is the SealedBox of 3872B → 3920B, placed at bytes [88:4008]
    # frame layout: [24B nonce][64B outer_header][3920B layer1][88B padding]
    LAYER1_SIZE = 3920
    onion_blob = bytes(frame[NONCE_SIZE + HEADER_SIZE : NONCE_SIZE + HEADER_SIZE + LAYER1_SIZE])

    box   = nacl.public.SealedBox(key_hier.x25519_private)
    inner = box.decrypt(onion_blob)   # 3920 - 48 = 3872B

    # First 64B of inner is the *next-hop* routing header
    next_header_raw = inner[:HEADER_SIZE]
    inner_payload   = inner[HEADER_SIZE:]

    header = unpack_header(next_header_raw)
    return header, inner_payload


# ---------------------------------------------------------------------------
# High-level convenience builder (used by other domains via mock)
# ---------------------------------------------------------------------------

def build_chat_packet(
    message:      str,
    routing_path: List[NodeDescriptor],
) -> bytearray:
    """Convenience wrapper: build a CHAT onion packet."""
    return build_onion_packet(message, routing_path, opcode=Opcode.CHAT)


def build_ping_packet(routing_path: List[NodeDescriptor]) -> bytearray:
    """Convenience wrapper: build a PING onion packet."""
    return build_onion_packet(b"PING", routing_path, opcode=Opcode.PING)