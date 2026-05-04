import nacl.utils
from pathlib import Path
from typing import List
from src.onion_crypto import (
    KeyHierarchy,
    NodeDescriptor,
    build_onion_packet,
    encrypt_e2e_handshake,
    decrypt_e2e_handshake,
    encrypt_e2e_session,
    decrypt_e2e_session,
    Opcode,
    E2E_PLAINTEXT_SIZE,
    E2E_BLOCK_SIZE,
)
import nacl.public
import nacl.secret


class CryptoWrapper:
    def __init__(self, keys_dir="keys"):
        self.keys_dir      = Path(keys_dir)
        self.key_hierarchy = KeyHierarchy(key_dir=self.keys_dir)
        self.key_hierarchy.initialise()
        self.session_keys  = {}

    def get_ed25519_pubkey(self):
        return bytes(self.key_hierarchy.verify_key).hex()

    def get_x25519_pubkey(self):
        return bytes(self.key_hierarchy.x25519_public).hex()

    def get_x25519_pubkey_bytes(self):
        return bytes(self.key_hierarchy.x25519_public)

    def sign(self, data: bytes) -> bytes:
        return bytes(self.key_hierarchy.signing_key.sign(data).signature)

    def encrypt_handshake(self, plaintext: bytes, peer_x25519_hex: str) -> bytes:
        if len(plaintext) != E2E_PLAINTEXT_SIZE:
            raise ValueError(f"Plaintext must be {E2E_PLAINTEXT_SIZE} bytes")
        peer_pubkey = nacl.public.PublicKey(bytes.fromhex(peer_x25519_hex))
        ciphertext  = encrypt_e2e_handshake(plaintext, peer_pubkey)
        if len(ciphertext) != E2E_BLOCK_SIZE:
            raise ValueError(f"Ciphertext must be {E2E_BLOCK_SIZE} bytes")
        return ciphertext

    def decrypt_handshake(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != E2E_BLOCK_SIZE:
            raise ValueError(f"Ciphertext must be {E2E_BLOCK_SIZE} bytes")
        plaintext = decrypt_e2e_handshake(ciphertext, self.key_hierarchy.x25519_private)
        if len(plaintext) != E2E_PLAINTEXT_SIZE:
            raise ValueError(f"Plaintext must be {E2E_PLAINTEXT_SIZE} bytes")
        return plaintext

    def establish_session(self, peer_x25519_hex: str):
        peer_pubkey = nacl.public.PublicKey(bytes.fromhex(peer_x25519_hex))
        box = nacl.public.Box(self.key_hierarchy.x25519_private, peer_pubkey)
        self.session_keys[peer_x25519_hex] = box.shared_key()

    def encrypt_session(self, plaintext: bytes, peer_x25519_hex: str) -> bytes:
        if len(plaintext) != E2E_PLAINTEXT_SIZE:
            raise ValueError(f"Plaintext must be {E2E_PLAINTEXT_SIZE} bytes")
        if peer_x25519_hex not in self.session_keys:
            self.establish_session(peer_x25519_hex)
        ciphertext = encrypt_e2e_session(plaintext, self.session_keys[peer_x25519_hex])
        if len(ciphertext) != E2E_BLOCK_SIZE:
            raise ValueError(f"Ciphertext must be {E2E_BLOCK_SIZE} bytes")
        return ciphertext

    def decrypt_session(self, ciphertext: bytes, peer_x25519_hex: str) -> bytes:
        if len(ciphertext) != E2E_BLOCK_SIZE:
            raise ValueError(f"Ciphertext must be {E2E_BLOCK_SIZE} bytes")
        if peer_x25519_hex not in self.session_keys:
            self.establish_session(peer_x25519_hex)
        plaintext = decrypt_e2e_session(ciphertext, self.session_keys[peer_x25519_hex])
        if len(plaintext) != E2E_PLAINTEXT_SIZE:
            raise ValueError(f"Plaintext must be {E2E_PLAINTEXT_SIZE} bytes")
        return plaintext

    def build_onion_packet(self, e2e_block: bytes, descriptors: List[NodeDescriptor], destination: NodeDescriptor) -> bytes:
        wire_packet = build_onion_packet(
            plaintext=e2e_block,
            routing_path=descriptors,
            destination=destination,
            opcode=Opcode.CHAT,
        )
        return bytes(wire_packet)
