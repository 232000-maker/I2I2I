"""
Crypto Wrapper - Client Domain Interface to Crypto Domain
Wraps onion_crypto.py functions for client domain use
"""

import nacl.utils
from pathlib import Path
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
    """
    Adapter between client domain and crypto domain
    Provides clean interface for client to use crypto operations
    """
    
    def __init__(self, keys_dir="keys"):
        self.keys_dir = Path(keys_dir)
        self.key_hierarchy = KeyHierarchy(key_dir=self.keys_dir)
        self.key_hierarchy.initialise()
        
        # Session keys (peer_x25519_hex -> shared_secret)
        self.session_keys = {}
    
    def get_ed25519_pubkey(self):
        """Return Ed25519 public key as hex string"""
        return bytes(self.key_hierarchy.verify_key).hex()
    
    def get_x25519_pubkey(self):
        """Return X25519 public key as hex string"""
        return bytes(self.key_hierarchy.x25519_public).hex()
    
    def get_x25519_pubkey_bytes(self):
        """Return X25519 public key as bytes"""
        return bytes(self.key_hierarchy.x25519_public)
    
    # ===== E2E ENCRYPTION (HANDSHAKE MODE) =====
    
    def encrypt_handshake(self, plaintext: bytes, peer_x25519_hex: str) -> bytes:
        """
        Encrypt for handshake using SealedBox
        Input: 3584 bytes plaintext
        Output: 3632 bytes ciphertext
        """
        if len(plaintext) != E2E_PLAINTEXT_SIZE:
            raise ValueError(f"Plaintext must be {E2E_PLAINTEXT_SIZE} bytes")
        
        peer_pubkey = nacl.public.PublicKey(bytes.fromhex(peer_x25519_hex))
        ciphertext = encrypt_e2e_handshake(plaintext, peer_pubkey)
        
        if len(ciphertext) != E2E_BLOCK_SIZE:
            raise ValueError(f"Ciphertext must be {E2E_BLOCK_SIZE} bytes")
        
        return ciphertext
    
    def decrypt_handshake(self, ciphertext: bytes) -> bytes:
        """
        Decrypt handshake using SealedBox
        Input: 3632 bytes ciphertext
        Output: 3584 bytes plaintext
        """
        if len(ciphertext) != E2E_BLOCK_SIZE:
            raise ValueError(f"Ciphertext must be {E2E_BLOCK_SIZE} bytes")
        
        plaintext = decrypt_e2e_handshake(ciphertext, self.key_hierarchy.x25519_private)
        
        if len(plaintext) != E2E_PLAINTEXT_SIZE:
            raise ValueError(f"Plaintext must be {E2E_PLAINTEXT_SIZE} bytes")
        
        return plaintext
    
    # ===== E2E ENCRYPTION (SESSION MODE) =====
    
    def establish_session(self, peer_x25519_hex: str):
        """
        Establish shared secret for session mode using DH
        """
        peer_pubkey = nacl.public.PublicKey(bytes.fromhex(peer_x25519_hex))
        box = nacl.public.Box(self.key_hierarchy.x25519_private, peer_pubkey)
        # Store the shared secret (32 bytes)
        self.session_keys[peer_x25519_hex] = box.shared_key()
    
    def encrypt_session(self, plaintext: bytes, peer_x25519_hex: str) -> bytes:
        """
        Encrypt for session using SecretBox
        Input: 3584 bytes plaintext
        Output: 3632 bytes ciphertext
        """
        if len(plaintext) != E2E_PLAINTEXT_SIZE:
            raise ValueError(f"Plaintext must be {E2E_PLAINTEXT_SIZE} bytes")
        
        if peer_x25519_hex not in self.session_keys:
            self.establish_session(peer_x25519_hex)
        
        shared_secret = self.session_keys[peer_x25519_hex]
        ciphertext = encrypt_e2e_session(plaintext, shared_secret)
        
        if len(ciphertext) != E2E_BLOCK_SIZE:
            raise ValueError(f"Ciphertext must be {E2E_BLOCK_SIZE} bytes")
        
        return ciphertext
    
    def decrypt_session(self, ciphertext: bytes, peer_x25519_hex: str) -> bytes:
        """
        Decrypt session using SecretBox
        Input: 3632 bytes ciphertext
        Output: 3584 bytes plaintext
        """
        if len(ciphertext) != E2E_BLOCK_SIZE:
            raise ValueError(f"Ciphertext must be {E2E_BLOCK_SIZE} bytes")
        
        if peer_x25519_hex not in self.session_keys:
            self.establish_session(peer_x25519_hex)
        
        shared_secret = self.session_keys[peer_x25519_hex]
        plaintext = decrypt_e2e_session(ciphertext, shared_secret)
        
        if len(plaintext) != E2E_PLAINTEXT_SIZE:
            raise ValueError(f"Plaintext must be {E2E_PLAINTEXT_SIZE} bytes")
        
        return plaintext
    
    # ===== ONION PACKET BUILDING =====
    
    def build_onion_packet(self, e2e_block: bytes, circuit: list) -> bytes:
        """
        Build 3-layer onion packet
        Input: 3632-byte E2E block + circuit (list of relay info)
        Output: 4096-byte wire packet
        
        circuit format: [
            {"x25519_pubkey": hex, "ip": str, "port": int},
            ...
        ]
        """
        # Convert circuit format to NodeDescriptor objects
        node_descriptors = []
        for relay in circuit:
            desc = NodeDescriptor(
                ed25519_pubkey=b'\x00' * 32,  # Not needed for packet building
                x25519_pubkey=bytes.fromhex(relay["x25519_pubkey"]),
                ip=relay["ip"],
                port=relay["port"]
            )
            node_descriptors.append(desc)
        
        # Use crypto domain's build_onion_packet
        # It expects plaintext, so we pass the e2e_block as the payload
        wire_packet = build_onion_packet(
            plaintext=e2e_block,
            routing_path=node_descriptors,
            opcode=Opcode.CHAT
        )
        
        return bytes(wire_packet)