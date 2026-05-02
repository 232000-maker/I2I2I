# tests/test_onion_crypto.py
"""
Test suite for src/onion_crypto.py
===================================
Covers:
  - Constants / struct layout assertions
  - Key hierarchy (generation, persistence, derivation rules)
  - Header pack/unpack round-trip
  - Wire frame assembly / disassembly
  - E2E encryption invariant (handshake and session indistinguishability)
  - Last-mile delivery block
  - Onion builder: 3-hop layer math + final 4096B output
  - Trial peel: layer-by-layer decryption
  - Opcode namespace
  - Edge cases: oversized payloads, wrong frame size, wrong key
"""

import os
import sys
import struct
import tempfile
import shutil
from pathlib import Path

import pytest
import nacl.signing
import nacl.public
import nacl.secret
import nacl.utils
import nacl.exceptions

# Make sure imports resolve from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.onion_crypto import (
    # Constants
    FRAME_SIZE, NONCE_SIZE, HEADER_SIZE, PAYLOAD_SIZE, PADDING_SIZE,
    HEADER_FORMAT, HEADER_FIELDS, SEALEDBOX_OVERHEAD, SECRETBOX_OVERHEAD,
    E2E_BLOCK_SIZE, E2E_PLAINTEXT_SIZE, E2E_SESSION_NOISE, LAST_MILE_NOISE,
    HOP1_OFFSET, HOP2_OFFSET, HOP3_OFFSET, OFFSET_STEP,
    # Classes
    Opcode, KeyHierarchy, NodeDescriptor,
    # Functions
    pack_header, unpack_header,
    assemble_frame, disassemble_frame,
    encrypt_e2e_handshake, decrypt_e2e_handshake,
    encrypt_e2e_session, decrypt_e2e_session,
    build_last_mile_block, extract_e2e_block,
    build_onion_packet, trial_peel,
    build_chat_packet, build_ping_packet,
)


# ---------------------------------------------------------------------------
# Helpers / Fixtures
# ---------------------------------------------------------------------------

def _make_node() -> tuple:
    """Generate a fresh Ed25519 key pair and derive X25519 keys. Returns (signing_key, x25519_pub)."""
    sk = nacl.signing.SigningKey.generate()
    x_priv = sk.to_curve25519_private_key()
    x_pub  = x_priv.public_key
    return sk, x_priv, x_pub


def _make_descriptor(ip="127.0.0.1", port=9000) -> tuple:
    """Return (NodeDescriptor, x25519_private_key) for a fresh node."""
    sk, x_priv, x_pub = _make_node()
    desc = NodeDescriptor(
        ed25519_pubkey=bytes(sk.verify_key),
        x25519_pubkey=bytes(x_pub),
        ip=ip,
        port=port,
    )
    return desc, x_priv


@pytest.fixture
def three_hop_path():
    """Returns ([desc1, desc2, desc3], [priv1, priv2, priv3])."""
    d1, p1 = _make_descriptor("10.0.0.1", 7001)
    d2, p2 = _make_descriptor("10.0.0.2", 7002)
    d3, p3 = _make_descriptor("10.0.0.3", 7003)
    return [d1, d2, d3], [p1, p2, p3]


@pytest.fixture
def key_hier(tmp_path):
    """A fully initialised KeyHierarchy backed by a temp directory."""
    kh = KeyHierarchy(key_dir=tmp_path / "keys")
    kh.initialise()
    return kh


# ---------------------------------------------------------------------------
# 1. Constants & Struct Layout
# ---------------------------------------------------------------------------

class TestConstants:
    def test_frame_total(self):
        assert NONCE_SIZE + HEADER_SIZE + PAYLOAD_SIZE + PADDING_SIZE == FRAME_SIZE

    def test_frame_size_is_4096(self):
        assert FRAME_SIZE == 4096

    def test_header_struct_size(self):
        assert HEADER_FIELDS == 64

    def test_e2e_handshake_invariant(self):
        """3584 + 48 = 3632"""
        assert E2E_PLAINTEXT_SIZE + SEALEDBOX_OVERHEAD == E2E_BLOCK_SIZE

    def test_e2e_session_invariant(self):
        """3584 + 8 + 40 = 3632"""
        assert E2E_PLAINTEXT_SIZE + E2E_SESSION_NOISE + SECRETBOX_OVERHEAD == E2E_BLOCK_SIZE

    def test_offset_step(self):
        assert HOP2_OFFSET - HOP3_OFFSET == OFFSET_STEP
        assert HOP1_OFFSET - HOP2_OFFSET == OFFSET_STEP
        assert OFFSET_STEP == 112

    def test_last_mile_layout(self):
        assert E2E_BLOCK_SIZE + LAST_MILE_NOISE == FRAME_SIZE


# ---------------------------------------------------------------------------
# 2. Opcode Namespace
# ---------------------------------------------------------------------------

class TestOpcodes:
    def test_all_opcodes_defined(self):
        assert Opcode.REG  == 0x00
        assert Opcode.SYN  == 0x01
        assert Opcode.CHAT == 0x02
        assert Opcode.FILE == 0x03
        assert Opcode.ACK  == 0x04
        assert Opcode.PING == 0x05
        assert Opcode.PONG == 0x06
        assert Opcode.SACK == 0x07
        assert Opcode.ERR  == 0xFF

    def test_opcodes_fit_in_one_byte(self):
        for op in [Opcode.REG, Opcode.SYN, Opcode.CHAT, Opcode.FILE,
                   Opcode.ACK, Opcode.PING, Opcode.PONG, Opcode.SACK, Opcode.ERR]:
            assert 0 <= op <= 255


# ---------------------------------------------------------------------------
# 3. Key Hierarchy
# ---------------------------------------------------------------------------

class TestKeyHierarchy:
    def test_generates_keys_on_first_run(self, tmp_path):
        kh = KeyHierarchy(key_dir=tmp_path / "keys")
        kh.initialise()
        assert (tmp_path / "keys" / "identity.key").exists()
        assert (tmp_path / "keys" / "identity.pub").exists()
        assert (tmp_path / "keys" / "x25519.pub").exists()

    def test_keys_are_correct_types(self, tmp_path):
        kh = KeyHierarchy(key_dir=tmp_path / "keys")
        kh.initialise()
        assert isinstance(kh.signing_key,   nacl.signing.SigningKey)
        assert isinstance(kh.verify_key,    nacl.signing.VerifyKey)
        assert isinstance(kh.x25519_private, nacl.public.PrivateKey)
        assert isinstance(kh.x25519_public,  nacl.public.PublicKey)

    def test_x25519_pubkey_length(self, tmp_path):
        kh = KeyHierarchy(key_dir=tmp_path / "keys")
        kh.initialise()
        assert len(bytes(kh.x25519_public)) == 32

    def test_load_persisted_key(self, tmp_path):
        key_dir = tmp_path / "keys"
        kh1 = KeyHierarchy(key_dir=key_dir)
        kh1.initialise()
        pub1 = bytes(kh1.x25519_public)

        kh2 = KeyHierarchy(key_dir=key_dir)
        kh2.initialise()
        pub2 = bytes(kh2.x25519_public)

        assert pub1 == pub2, "Reloaded key should match original"

    def test_no_access_before_init(self, tmp_path):
        kh = KeyHierarchy(key_dir=tmp_path / "keys")
        with pytest.raises(RuntimeError):
            _ = kh.signing_key

    def test_sign_produces_bytes(self, key_hier):
        signed = key_hier.sign(b"hello world")
        assert isinstance(signed, bytes)
        assert len(signed) > 0

    def test_sign_verifiable(self, key_hier):
        msg = b"test payload"
        signed = key_hier.sign(msg)
        # PyNaCl signed messages include the original; verify by stripping
        verified = key_hier.verify_key.verify(signed)
        assert verified == msg

    def test_derives_x25519_from_ed25519(self, tmp_path):
        """X25519 keys are deterministically derived from Ed25519 signing key."""
        key_dir = tmp_path / "keys"
        kh = KeyHierarchy(key_dir=key_dir)
        kh.initialise()

        # Manually re-derive and compare
        expected_priv = kh.signing_key.to_curve25519_private_key()
        assert bytes(kh.x25519_private) == bytes(expected_priv)


# ---------------------------------------------------------------------------
# 4. Header Pack / Unpack
# ---------------------------------------------------------------------------

class TestHeader:
    def test_pack_produces_64_bytes(self):
        _, _, x_pub = _make_node()
        raw = pack_header(Opcode.CHAT, bytes(x_pub), "192.168.1.1", 9000)
        assert len(raw) == 64

    def test_round_trip(self):
        _, _, x_pub = _make_node()
        pub_bytes = bytes(x_pub)
        raw = pack_header(Opcode.SYN, pub_bytes, "10.0.0.5", 1234)
        h = unpack_header(raw)
        assert h["opcode"]      == Opcode.SYN
        assert h["dest_pubkey"] == pub_bytes
        assert h["next_ip"]     == "10.0.0.5"
        assert h["next_port"]   == 1234

    def test_wrong_pubkey_length_raises(self):
        with pytest.raises(ValueError):
            pack_header(Opcode.CHAT, b"\x00" * 31, "127.0.0.1", 9000)

    def test_unpack_wrong_size_raises(self):
        with pytest.raises(ValueError):
            unpack_header(b"\x00" * 63)

    def test_random_noise_differs_each_call(self):
        _, _, x_pub = _make_node()
        pub = bytes(x_pub)
        r1 = pack_header(Opcode.CHAT, pub, "127.0.0.1", 9000)
        r2 = pack_header(Opcode.CHAT, pub, "127.0.0.1", 9000)
        # Last 25 bytes are noise — should statistically differ
        assert r1[39:] != r2[39:]  # almost certain over 25 random bytes


# ---------------------------------------------------------------------------
# 5. Wire Frame Assembly
# ---------------------------------------------------------------------------

class TestWireFrame:
    def test_assemble_produces_4096_bytes(self):
        nonce   = nacl.utils.random(NONCE_SIZE)
        _, _, x = _make_node()
        header  = pack_header(Opcode.CHAT, bytes(x), "127.0.0.1", 9000)
        payload = nacl.utils.random(PAYLOAD_SIZE)
        frame   = assemble_frame(nonce, header, payload)
        assert len(frame) == FRAME_SIZE

    def test_assemble_returns_bytearray(self):
        nonce   = nacl.utils.random(NONCE_SIZE)
        _, _, x = _make_node()
        header  = pack_header(Opcode.CHAT, bytes(x), "127.0.0.1", 9000)
        payload = nacl.utils.random(PAYLOAD_SIZE)
        frame   = assemble_frame(nonce, header, payload)
        assert isinstance(frame, bytearray)

    def test_disassemble_round_trip(self):
        nonce   = nacl.utils.random(NONCE_SIZE)
        _, _, x = _make_node()
        header  = pack_header(Opcode.CHAT, bytes(x), "127.0.0.1", 9000)
        payload = nacl.utils.random(PAYLOAD_SIZE)
        frame   = assemble_frame(nonce, header, payload)

        n2, h2, p2 = disassemble_frame(frame)
        assert n2 == nonce
        assert h2 == header
        assert p2 == payload

    def test_disassemble_wrong_size_raises(self):
        with pytest.raises(ValueError):
            disassemble_frame(b"\x00" * 100)


# ---------------------------------------------------------------------------
# 6. E2E Encryption — Indistinguishability Invariant
# ---------------------------------------------------------------------------

class TestE2EEncryption:
    def test_handshake_output_is_3632_bytes(self):
        _, x_priv, x_pub = _make_node()
        pt = nacl.utils.random(E2E_PLAINTEXT_SIZE)
        ct = encrypt_e2e_handshake(pt, x_pub)
        assert len(ct) == E2E_BLOCK_SIZE

    def test_session_output_is_3632_bytes(self):
        pt     = nacl.utils.random(E2E_PLAINTEXT_SIZE)
        secret = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        ct     = encrypt_e2e_session(pt, secret)
        assert len(ct) == E2E_BLOCK_SIZE

    def test_both_e2e_paths_produce_same_size(self):
        _, x_priv, x_pub = _make_node()
        pt     = nacl.utils.random(E2E_PLAINTEXT_SIZE)
        secret = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

        ct_hs  = encrypt_e2e_handshake(pt, x_pub)
        ct_ses = encrypt_e2e_session(pt, secret)

        assert len(ct_hs) == len(ct_ses) == E2E_BLOCK_SIZE

    def test_handshake_decrypt_round_trip(self):
        _, x_priv, x_pub = _make_node()
        pt = nacl.utils.random(E2E_PLAINTEXT_SIZE)
        ct = encrypt_e2e_handshake(pt, x_pub)
        recovered = decrypt_e2e_handshake(ct, x_priv)
        assert recovered == pt

    def test_session_decrypt_round_trip(self):
        pt     = nacl.utils.random(E2E_PLAINTEXT_SIZE)
        secret = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        ct     = encrypt_e2e_session(pt, secret)
        recovered = decrypt_e2e_session(ct, secret)
        assert recovered == pt

    def test_handshake_wrong_key_raises(self):
        _, x_priv, x_pub = _make_node()
        _, wrong_priv, _ = _make_node()
        pt = nacl.utils.random(E2E_PLAINTEXT_SIZE)
        ct = encrypt_e2e_handshake(pt, x_pub)
        with pytest.raises(nacl.exceptions.CryptoError):
            decrypt_e2e_handshake(ct, wrong_priv)

    def test_session_wrong_key_raises(self):
        pt      = nacl.utils.random(E2E_PLAINTEXT_SIZE)
        secret  = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        wrong   = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        ct      = encrypt_e2e_session(pt, secret)
        with pytest.raises(nacl.exceptions.CryptoError):
            decrypt_e2e_session(ct, wrong)

    def test_handshake_wrong_plaintext_size_raises(self):
        _, _, x_pub = _make_node()
        with pytest.raises(ValueError):
            encrypt_e2e_handshake(b"too short", x_pub)

    def test_session_wrong_plaintext_size_raises(self):
        secret = nacl.utils.random(32)
        with pytest.raises(ValueError):
            encrypt_e2e_session(b"too short", secret)


# ---------------------------------------------------------------------------
# 7. Last-Mile Block
# ---------------------------------------------------------------------------

class TestLastMile:
    def test_block_is_4096_bytes(self):
        e2e = nacl.utils.random(E2E_BLOCK_SIZE)
        block = build_last_mile_block(e2e)
        assert len(block) == FRAME_SIZE

    def test_block_is_bytearray(self):
        e2e   = nacl.utils.random(E2E_BLOCK_SIZE)
        block = build_last_mile_block(e2e)
        assert isinstance(block, bytearray)

    def test_extract_recovers_e2e_block(self):
        e2e   = nacl.utils.random(E2E_BLOCK_SIZE)
        block = build_last_mile_block(e2e)
        recovered = extract_e2e_block(block)
        assert recovered == bytes(e2e)

    def test_extract_wrong_size_raises(self):
        with pytest.raises(ValueError):
            extract_e2e_block(b"\x00" * 100)


# ---------------------------------------------------------------------------
# 8. Onion Builder — Layer Math + 4096B Output Gate
# ---------------------------------------------------------------------------

class TestOnionBuilder:
    def test_output_is_exactly_4096_bytes(self, three_hop_path):
        path, _ = three_hop_path
        frame = build_onion_packet(b"Hello Onion!", path)
        assert len(frame) == FRAME_SIZE

    def test_output_is_bytearray(self, three_hop_path):
        path, _ = three_hop_path
        frame = build_onion_packet(b"test", path)
        assert isinstance(frame, bytearray)

    def test_string_input_works(self, three_hop_path):
        path, _ = three_hop_path
        frame = build_onion_packet("string message", path)
        assert len(frame) == FRAME_SIZE

    def test_max_size_payload(self, three_hop_path):
        path, _ = three_hop_path
        big = nacl.utils.random(E2E_PLAINTEXT_SIZE)
        frame = build_onion_packet(big, path)
        assert len(frame) == FRAME_SIZE

    def test_oversized_payload_raises(self, three_hop_path):
        path, _ = three_hop_path
        with pytest.raises(ValueError):
            build_onion_packet(b"x" * (E2E_PLAINTEXT_SIZE + 1), path)

    def test_wrong_hop_count_raises(self):
        d1, _ = _make_descriptor()
        d2, _ = _make_descriptor()
        with pytest.raises(ValueError):
            build_onion_packet(b"msg", [d1, d2])  # only 2 hops

    def test_different_packets_are_not_identical(self, three_hop_path):
        """Two encryptions of the same plaintext must differ (probabilistic encryption)."""
        path, _ = three_hop_path
        f1 = build_onion_packet(b"same message", path)
        f2 = build_onion_packet(b"same message", path)
        assert f1 != f2

    def test_chat_packet_convenience(self, three_hop_path):
        path, _ = three_hop_path
        frame = build_chat_packet("hello", path)
        assert len(frame) == FRAME_SIZE

    def test_ping_packet_convenience(self, three_hop_path):
        path, _ = three_hop_path
        frame = build_ping_packet(path)
        assert len(frame) == FRAME_SIZE

    def test_multiple_opcodes(self, three_hop_path):
        path, _ = three_hop_path
        for opcode in [Opcode.CHAT, Opcode.FILE, Opcode.PING, Opcode.SYN]:
            frame = build_onion_packet(b"payload", path, opcode=opcode)
            assert len(frame) == FRAME_SIZE


# ---------------------------------------------------------------------------
# 9. Trial Peel — Layer-by-Layer Decryption
# ---------------------------------------------------------------------------

class TestTrialPeel:
    def _make_kh_from_priv(self, x_priv: nacl.public.PrivateKey, tmp_path) -> KeyHierarchy:
        """Inject a known X25519 private key into a KeyHierarchy for testing."""
        kh = KeyHierarchy.__new__(KeyHierarchy)
        kh._key_dir = tmp_path
        sk = nacl.signing.SigningKey.generate()
        kh._signing_key  = sk
        kh._verify_key   = sk.verify_key
        kh._x25519_private = x_priv
        kh._x25519_public  = x_priv.public_key
        return kh

    def test_hop1_peel_succeeds(self, three_hop_path, tmp_path):
        path, privkeys = three_hop_path
        frame = build_onion_packet(b"peeling test", path)
        kh1 = self._make_kh_from_priv(privkeys[0], tmp_path)
        header, inner = trial_peel(frame, kh1)
        assert isinstance(header, dict)
        assert "opcode" in header
        assert isinstance(inner, bytes)

    def test_wrong_key_raises_crypto_error(self, three_hop_path, tmp_path):
        path, _ = three_hop_path
        frame = build_onion_packet(b"wrong key test", path)
        _, wrong_priv, _ = _make_node()
        kh_wrong = self._make_kh_from_priv(wrong_priv, tmp_path)
        with pytest.raises(nacl.exceptions.CryptoError):
            trial_peel(frame, kh_wrong)

    def test_wrong_frame_size_raises(self, tmp_path):
        _, x_priv, _ = _make_node()
        kh = self._make_kh_from_priv(x_priv, tmp_path)
        with pytest.raises(ValueError):
            trial_peel(b"\x00" * 100, kh)


# ---------------------------------------------------------------------------
# 10. Node Descriptor
# ---------------------------------------------------------------------------

class TestNodeDescriptor:
    def test_descriptor_stores_fields(self):
        sk, _, x_pub = _make_node()
        desc = NodeDescriptor(
            ed25519_pubkey=bytes(sk.verify_key),
            x25519_pubkey=bytes(x_pub),
            ip="192.168.0.1",
            port=8080,
        )
        assert desc.ip   == "192.168.0.1"
        assert desc.port == 8080
        assert len(desc.x25519_pubkey) == 32
        assert len(desc.ed25519_pubkey) == 32
