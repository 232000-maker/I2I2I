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

logger = logging.getLogger(__name__)

FRAME_SIZE = 4096
NONCE_SIZE = 24
HEADER_SIZE = 64
PAYLOAD_SIZE = 3632
PADDING_SIZE = 376
LAST_MILE_NOISE = 464

HEADER_FORMAT = "!B 32s 4s H 25s"
HEADER_FIELDS = struct.calcsize(HEADER_FORMAT)
assert HEADER_FIELDS == HEADER_SIZE, (
    f"Header struct mismatch: {HEADER_FIELDS} != {HEADER_SIZE}"
)

OFFSET_STEP = 112
SEALEDBOX_OVERHEAD = 48
SECRETBOX_OVERHEAD = 40

E2E_PLAINTEXT_SIZE = 3584
E2E_BLOCK_SIZE = 3632
E2E_SESSION_NOISE = 8

# Onion blob sizes when e2e_block (3632B) is the innermost payload.
# Each hop's blob = previous inner_plain + SEALEDBOX_OVERHEAD.
# inner_plain_3 = header(64) + e2e_block(3632) = 3696 → layer3 = 3744
# inner_plain_2 = header(64) + layer3(3744)    = 3808 → layer2 = 3856
# inner_plain_1 = header(64) + layer2(3856)    = 3920 → layer1 = 3968
# frame = 24 + 64 + 3968 + 40(padding) = 4096 ✓
HOP1_BLOB_SIZE = 3968
HOP2_BLOB_SIZE = 3856
HOP3_BLOB_SIZE = 3744
BLOB_SIZES = [HOP1_BLOB_SIZE, HOP2_BLOB_SIZE, HOP3_BLOB_SIZE]

INNER_PLAIN_3_SIZE = HEADER_SIZE + E2E_BLOCK_SIZE  # 3696
INNER_PLAIN_2_SIZE = HEADER_SIZE + HOP3_BLOB_SIZE  # 3808
INNER_PLAIN_1_SIZE = HEADER_SIZE + HOP2_BLOB_SIZE  # 3920


class Opcode:
    REG = 0x00
    SYN = 0x01
    CHAT = 0x02
    FILE = 0x03
    ACK = 0x04
    PING = 0x05
    PONG = 0x06
    SACK = 0x07
    ERR = 0xFF


KEY_DIR = Path("keys")
IDENTITY_KEY = KEY_DIR / "identity.key"
IDENTITY_PUB = KEY_DIR / "identity.pub"
X25519_PUB = KEY_DIR / "x25519.pub"


class KeyHierarchy:
    def __init__(self, key_dir: Path = KEY_DIR):
        self._key_dir = key_dir
        self._signing_key = None
        self._verify_key = None
        self._x25519_private = None
        self._x25519_public = None

    def initialise(self) -> None:
        self._key_dir.mkdir(parents=True, exist_ok=True)

        id_key_path = self._key_dir / "identity.key"
        id_pub_path = self._key_dir / "identity.pub"
        x_pub_path = self._key_dir / "x25519.pub"

        if id_key_path.exists():
            raw = id_key_path.read_bytes()
            self._signing_key = nacl.signing.SigningKey(raw)
        else:
            self._signing_key = nacl.signing.SigningKey.generate()
            id_key_path.write_bytes(bytes(self._signing_key))

        self._verify_key = self._signing_key.verify_key

        if not id_pub_path.exists():
            id_pub_path.write_bytes(bytes(self._verify_key))

        self._x25519_private = self._signing_key.to_curve25519_private_key()
        self._x25519_public = self._x25519_private.public_key

        if not x_pub_path.exists():
            x_pub_path.write_bytes(bytes(self._x25519_public))

        logger.info(
            "KeyHierarchy initialised. X25519 pub: %s",
            bytes(self._x25519_public).hex()[:16] + "...",
        )

    @property
    def signing_key(self):
        self._assert_init()
        return self._signing_key

    @property
    def verify_key(self):
        self._assert_init()
        return self._verify_key

    @property
    def x25519_private(self):
        self._assert_init()
        return self._x25519_private

    @property
    def x25519_public(self):
        self._assert_init()
        return self._x25519_public

    def sign(self, data: bytes) -> bytes:
        self._assert_init()
        return bytes(self._signing_key.sign(data))

    def _assert_init(self):
        if self._signing_key is None:
            raise RuntimeError("KeyHierarchy.initialise() must be called before use.")


def pack_header(opcode: int, dest_pubkey: bytes, next_ip: str, next_port: int) -> bytes:
    if len(dest_pubkey) != 32:
        raise ValueError(f"dest_pubkey must be 32 bytes, got {len(dest_pubkey)}")
    # Bug 1 fix: resolve hostnames (e.g. Docker service names) to dotted-decimal
    # IPs before packing. socket.inet_aton only accepts dotted-decimal strings,
    # so passing a Docker hostname like "relay-1" would raise OSError.
    packed_ip = socket.inet_aton(socket.gethostbyname(next_ip))
    noise = nacl.utils.random(25)
    raw = struct.pack(HEADER_FORMAT, opcode, dest_pubkey, packed_ip, next_port, noise)
    assert len(raw) == HEADER_SIZE
    return raw


def unpack_header(raw: bytes) -> dict:
    if len(raw) != HEADER_SIZE:
        raise ValueError(f"Header must be {HEADER_SIZE} bytes, got {len(raw)}")
    opcode, dest_pubkey, packed_ip, next_port, _ = struct.unpack(HEADER_FORMAT, raw)
    next_ip = socket.inet_ntoa(packed_ip)
    return {
        "opcode": opcode,
        "dest_pubkey": dest_pubkey,
        "next_ip": next_ip,
        "next_port": next_port,
    }


def assemble_frame(nonce: bytes, header: bytes, payload: bytes) -> bytearray:
    assert len(nonce) == NONCE_SIZE
    assert len(header) == HEADER_SIZE
    assert len(payload) == PAYLOAD_SIZE

    padding = nacl.utils.random(PADDING_SIZE)
    frame = bytearray(nonce + header + payload + padding)
    assert len(frame) == FRAME_SIZE
    return frame


def disassemble_frame(frame) -> Tuple[bytes, bytes, bytes]:
    if len(frame) != FRAME_SIZE:
        raise ValueError(f"Frame must be {FRAME_SIZE} bytes, got {len(frame)}")
    nonce = bytes(frame[:NONCE_SIZE])
    header = bytes(frame[NONCE_SIZE : NONCE_SIZE + HEADER_SIZE])
    payload = bytes(
        frame[NONCE_SIZE + HEADER_SIZE : NONCE_SIZE + HEADER_SIZE + PAYLOAD_SIZE]
    )
    return nonce, header, payload


def encrypt_e2e_handshake(
    plaintext: bytes, dest_x25519_pub: nacl.public.PublicKey
) -> bytes:
    if len(plaintext) != E2E_PLAINTEXT_SIZE:
        raise ValueError(
            f"Handshake plaintext must be {E2E_PLAINTEXT_SIZE}B, got {len(plaintext)}"
        )
    box = nacl.public.SealedBox(dest_x25519_pub)
    ciphertext = box.encrypt(plaintext)
    assert len(ciphertext) == E2E_BLOCK_SIZE
    return ciphertext


def decrypt_e2e_handshake(
    ciphertext: bytes, x25519_private: nacl.public.PrivateKey
) -> bytes:
    box = nacl.public.SealedBox(x25519_private)
    return box.decrypt(ciphertext)


def encrypt_e2e_session(plaintext: bytes, shared_secret: bytes) -> bytes:
    if len(plaintext) != E2E_PLAINTEXT_SIZE:
        raise ValueError(
            f"Session plaintext must be {E2E_PLAINTEXT_SIZE}B, got {len(plaintext)}"
        )
    if len(shared_secret) != nacl.secret.SecretBox.KEY_SIZE:
        raise ValueError(f"Shared secret must be {nacl.secret.SecretBox.KEY_SIZE}B")
    noise = nacl.utils.random(E2E_SESSION_NOISE)
    padded = noise + plaintext
    box = nacl.secret.SecretBox(shared_secret)
    ciphertext = box.encrypt(padded)
    assert len(ciphertext) == E2E_BLOCK_SIZE
    return ciphertext


def decrypt_e2e_session(ciphertext: bytes, shared_secret: bytes) -> bytes:
    box = nacl.secret.SecretBox(shared_secret)
    padded = box.decrypt(ciphertext)
    return padded[E2E_SESSION_NOISE:]


def build_last_mile_block(e2e_block: bytes) -> bytes:
    assert len(e2e_block) == E2E_BLOCK_SIZE, (
        f"E2E block must be {E2E_BLOCK_SIZE}B, got {len(e2e_block)}"
    )
    noise = nacl.utils.random(LAST_MILE_NOISE)
    block = bytearray(e2e_block + noise)
    assert len(block) == FRAME_SIZE
    return block


def extract_e2e_block(last_mile) -> bytes:
    if len(last_mile) != FRAME_SIZE:
        raise ValueError(f"Last-mile block must be {FRAME_SIZE}B, got {len(last_mile)}")
    return bytes(last_mile[:E2E_BLOCK_SIZE])


class NodeDescriptor:
    __slots__ = ("ed25519_pubkey", "x25519_pubkey", "ip", "port")

    def __init__(self, ed25519_pubkey: bytes, x25519_pubkey: bytes, ip: str, port: int):
        self.ed25519_pubkey = ed25519_pubkey
        self.x25519_pubkey = x25519_pubkey
        self.ip = ip
        self.port = port


def build_onion_packet(
    plaintext: bytes,
    routing_path: List[NodeDescriptor],
    destination: NodeDescriptor,
    opcode: int = Opcode.CHAT,
) -> bytearray:
    """
    Build a fully padded, 4096-byte onion-encrypted wire packet.

    plaintext must be the already E2E-encrypted block (E2E_BLOCK_SIZE = 3632B).
    The three onion layers wrap this block for relay-hop confidentiality.

    Frame math with 3632B e2e_block as innermost payload:
      inner_plain_3 = header(64) + e2e_block(3632) = 3696B → layer3 = 3744B
      inner_plain_2 = header(64) + layer3(3744)    = 3808B → layer2 = 3856B
      inner_plain_1 = header(64) + layer2(3856)    = 3920B → layer1 = 3968B
      frame         = nonce(24) + header(64) + layer1(3968) + padding(40) = 4096B
    """
    if len(routing_path) != 3:
        raise ValueError("routing_path must contain exactly 3 NodeDescriptors")

    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    if len(plaintext) != E2E_BLOCK_SIZE:
        raise ValueError(
            f"plaintext must be the E2E-encrypted block: {E2E_BLOCK_SIZE}B, got {len(plaintext)}"
        )

    hop1, hop2, hop3 = routing_path

    def to_bytes(k):
        return k if isinstance(k, bytes) else bytes(k)

    def make_pub(k):
        return nacl.public.PublicKey(to_bytes(k))

    # Innermost layer: header routing to Bob's gateway, payload is the e2e_block
    header_for_hop3 = pack_header(
        opcode,
        to_bytes(destination.x25519_pubkey),
        destination.ip,
        destination.port,
    )
    inner_plain_3 = header_for_hop3 + plaintext  # 64 + 3632 = 3696B
    assert len(inner_plain_3) == INNER_PLAIN_3_SIZE, len(inner_plain_3)
    layer3 = nacl.public.SealedBox(make_pub(hop3.x25519_pubkey)).encrypt(inner_plain_3)
    assert len(layer3) == HOP3_BLOB_SIZE, len(layer3)  # 3744B

    # Middle layer: header routing to hop3
    header_for_hop2 = pack_header(
        opcode,
        to_bytes(hop3.x25519_pubkey),
        hop3.ip,
        hop3.port,
    )
    inner_plain_2 = header_for_hop2 + layer3  # 64 + 3744 = 3808B
    assert len(inner_plain_2) == INNER_PLAIN_2_SIZE, len(inner_plain_2)
    layer2 = nacl.public.SealedBox(make_pub(hop2.x25519_pubkey)).encrypt(inner_plain_2)
    assert len(layer2) == HOP2_BLOB_SIZE, len(layer2)  # 3856B

    # Outer layer: header routing to hop2
    header_for_hop1 = pack_header(
        opcode,
        to_bytes(hop2.x25519_pubkey),
        hop2.ip,
        hop2.port,
    )
    inner_plain_1 = header_for_hop1 + layer2  # 64 + 3856 = 3920B
    assert len(inner_plain_1) == INNER_PLAIN_1_SIZE, len(inner_plain_1)
    layer1 = nacl.public.SealedBox(make_pub(hop1.x25519_pubkey)).encrypt(inner_plain_1)
    assert len(layer1) == HOP1_BLOB_SIZE, len(layer1)  # 3968B

    nonce = nacl.utils.random(NONCE_SIZE)
    outer_h = pack_header(
        opcode,
        to_bytes(hop1.x25519_pubkey),
        hop1.ip,
        hop1.port,
    )

    # 24 + 64 + 3968 = 4056 → 40B tail padding
    tail_padding_size = FRAME_SIZE - NONCE_SIZE - HEADER_SIZE - len(layer1)
    assert tail_padding_size >= 0, f"Onion too large: overflow by {-tail_padding_size}B"
    tail_padding = nacl.utils.random(tail_padding_size)

    frame = bytearray(nonce + outer_h + layer1 + tail_padding)
    assert len(frame) == FRAME_SIZE, f"Frame {len(frame)}B != {FRAME_SIZE}B"
    return frame


def trial_peel(
    frame: bytes,
    key_hier: KeyHierarchy,
) -> Tuple[dict, bytes]:
    """
    Attempt to peel one onion layer from a 4096B frame.

    Tries blob sizes [3968, 3856, 3744] (hop1, hop2, hop3) in descending order.
    Returns (header_dict, inner_payload) on first successful decrypt.
    Raises the last CryptoError if none succeed.
    """
    if len(frame) != FRAME_SIZE:
        raise ValueError(f"Frame must be {FRAME_SIZE}B, got {len(frame)}")

    box = nacl.public.SealedBox(key_hier.x25519_private)
    last_exc = None

    for blob_size in BLOB_SIZES:
        onion_blob = bytes(
            frame[NONCE_SIZE + HEADER_SIZE : NONCE_SIZE + HEADER_SIZE + blob_size]
        )
        try:
            inner = box.decrypt(onion_blob)
            next_header_raw = inner[:HEADER_SIZE]
            inner_payload = inner[HEADER_SIZE:]
            header = unpack_header(next_header_raw)
            return header, inner_payload
        except Exception as e:
            last_exc = e
            continue

    raise last_exc


def build_chat_packet(
    message: str, routing_path: List[NodeDescriptor], destination: NodeDescriptor
) -> bytearray:
    return build_onion_packet(message, routing_path, destination, opcode=Opcode.CHAT)


def build_ping_packet(
    routing_path: List[NodeDescriptor], destination: NodeDescriptor
) -> bytearray:
    return build_onion_packet(b"PING", routing_path, destination, opcode=Opcode.PING)
