"""
Peer Connection State Machine
Tracks handshake progress, session state, and timeouts
"""

import time
import nacl.utils
from src.constants import *


class PeerConnection:
    """
    Manages connection state for a single peer
    Implements Alice's handshake flow and Bob's dual-state decryption
    """
    
    def __init__(self, peer_ed25519_pubkey, peer_x25519_pubkey=None):
        self.peer_ed25519 = peer_ed25519_pubkey
        self.peer_x25519 = peer_x25519_pubkey
        
        # Connection state
        self.state = STATE_IDLE
        self.decryption_mode = MODE_HANDSHAKE
        
        # Handshake tracking
        self.transaction_id = None
        self.circuit = None
        self.handshake_start_time = None
        self.retry_count = 0
        
        # Session tracking
        self.session_active = False
        self.last_activity = time.time()
        
        # Gateway info (from LeaseSet)
        self.gateway_ip = None
        self.gateway_port = None
    
    def initiate_handshake(self):
        """
        Alice's handshake initiation
        Returns: transaction_id
        """
        if self.state != STATE_IDLE and self.state != STATE_AWAITING_CIRCUIT:
            raise ValueError(f"Cannot initiate handshake from state {self.state}")
        
        # Generate transaction ID
        self.transaction_id = nacl.utils.random(16).hex()
        
        # Mark handshake start
        self.handshake_start_time = time.time()
        self.state = STATE_AWAITING_CIRCUIT
        
        return self.transaction_id
    
    def set_circuit(self, circuit):
        """Store selected relay circuit"""
        if self.state != STATE_AWAITING_CIRCUIT:
            raise ValueError(f"Circuit can only be set in AWAITING_CIRCUIT state")
        
        self.circuit = circuit
        self.state = STATE_AWAITING_ACK
    
    def set_leaseset(self, leaseset):
        """Store Bob's LeaseSet info"""
        self.peer_x25519 = leaseset.get("x25519_pubkey")
        self.gateway_ip = leaseset.get("gateway_ip")
        self.gateway_port = leaseset.get("gateway_port")
    
    def check_timeout(self):
        """
        Check if handshake has timed out (30s limit)
        Returns: True if timed out
        """
        if self.state in [STATE_AWAITING_CIRCUIT, STATE_AWAITING_ACK]:
            if self.handshake_start_time:
                elapsed = time.time() - self.handshake_start_time
                if elapsed > HANDSHAKE_TIMEOUT:
                    return True
        return False
    
    def can_retry(self):
        """Check if retry is allowed (max 3 retries)"""
        return self.retry_count < MAX_RETRIES
    
    def retry_handshake(self):
        """Retry handshake after timeout"""
        if not self.can_retry():
            raise ValueError("Maximum retries exceeded")
        
        self.retry_count += 1
        self.handshake_start_time = time.time()
        self.state = STATE_AWAITING_CIRCUIT
        self.transaction_id = nacl.utils.random(16).hex()
        
        return self.transaction_id
    
    def receive_ack(self):
        """
        Handle ACK reception - upgrade to session mode
        Bob's dual-state transition: HANDSHAKE → SESSION
        """
        if self.state != STATE_AWAITING_ACK:
            raise ValueError(f"Cannot receive ACK in state {self.state}")
        
        # Transition to session mode
        self.state = STATE_SESSION_ACTIVE
        self.decryption_mode = MODE_SESSION
        self.session_active = True
        self.last_activity = time.time()
    
    def get_decryption_mode(self):
        """
        Bob's dual-state decryption engine
        Returns: MODE_HANDSHAKE or MODE_SESSION
        """
        return self.decryption_mode
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()
    
    def is_active(self):
        """Check if session is still active"""
        return self.session_active and self.state == STATE_SESSION_ACTIVE
    
    def get_status(self):
        """Return human-readable status"""
        return {
            "peer": self.peer_ed25519[:16] if self.peer_ed25519 else "unknown",
            "state": self.state,
            "mode": self.decryption_mode,
            "session_active": self.session_active,
            "retry_count": self.retry_count,
            "transaction_id": self.transaction_id
        }