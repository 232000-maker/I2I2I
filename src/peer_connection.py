import time
import nacl.utils
from src.constants import *


class PeerConnection:
    def __init__(self, peer_ed25519_pubkey, peer_x25519_pubkey=None):
        self.peer_ed25519 = peer_ed25519_pubkey
        self.peer_x25519 = peer_x25519_pubkey
        self.state = STATE_IDLE
        self.decryption_mode = MODE_HANDSHAKE
        self.transaction_id = None
        self.circuit = None
        self.handshake_start_time = None
        self.retry_count = 0
        self.session_active = False
        self.last_activity = time.time()
        self.gateway_ip = None
        self.gateway_port = None

    def initiate_handshake(self):
        # Bug 1 fix: STATE_AWAITING_ACK must be an allowed origin state.
        #
        # When the ACK timeout fires the retry path calls initiate_handshake()
        # while the connection is still in STATE_AWAITING_ACK (the SYN was
        # sent but no ACK arrived).  The original guard only permitted
        # STATE_IDLE and STATE_AWAITING_CIRCUIT, so every timeout-triggered
        # retry crashed with:
        #   "Cannot initiate handshake from state AWAITING_ACK"
        #
        # Adding STATE_AWAITING_ACK lets the method act as a full reset from
        # any pre-session state, which is the caller's intent.
        if self.state not in (STATE_IDLE, STATE_AWAITING_CIRCUIT, STATE_AWAITING_ACK):
            raise ValueError(f"Cannot initiate handshake from state {self.state}")
        self.transaction_id = nacl.utils.random(16).hex()
        self.handshake_start_time = time.time()
        self.state = STATE_AWAITING_CIRCUIT
        self.circuit = None  # discard any stale circuit from prior attempt
        return self.transaction_id

    def set_circuit(self, circuit):
        if self.state != STATE_AWAITING_CIRCUIT:
            raise ValueError(f"Circuit can only be set in AWAITING_CIRCUIT state")
        self.circuit = circuit
        self.state = STATE_AWAITING_ACK

    def set_circuit_responder(self, circuit):
        self.circuit = circuit

    def set_leaseset(self, leaseset):
        self.peer_x25519 = leaseset.get("x25519_pubkey")
        self.gateway_ip = leaseset.get("gateway_ip")
        self.gateway_port = leaseset.get("gateway_port")

    def check_timeout(self):
        if self.state in (STATE_AWAITING_CIRCUIT, STATE_AWAITING_ACK):
            if self.handshake_start_time:
                if time.time() - self.handshake_start_time > HANDSHAKE_TIMEOUT:
                    return True
        return False

    def can_retry(self):
        return self.retry_count < MAX_RETRIES

    def retry_handshake(self):
        if not self.can_retry():
            raise ValueError("Maximum retries exceeded")
        self.retry_count += 1
        self.handshake_start_time = time.time()
        self.state = STATE_AWAITING_CIRCUIT
        # Bug 1 fix (secondary): clear the stale circuit so set_circuit() does
        # not operate on data from the previous (failed) attempt.
        self.circuit = None
        self.transaction_id = nacl.utils.random(16).hex()
        return self.transaction_id

    def receive_ack(self):
        if self.state != STATE_AWAITING_ACK:
            raise ValueError(f"Cannot receive ACK in state {self.state}")
        self._activate_session()

    def upgrade_to_session(self):
        self._activate_session()

    def _activate_session(self):
        self.state = STATE_SESSION_ACTIVE
        self.decryption_mode = MODE_SESSION
        self.session_active = True
        self.last_activity = time.time()

    def get_decryption_mode(self):
        return self.decryption_mode

    def update_activity(self):
        self.last_activity = time.time()

    def is_active(self):
        return self.session_active and self.state == STATE_SESSION_ACTIVE

    def get_status(self):
        return {
            "peer": self.peer_ed25519[:16] if self.peer_ed25519 else "unknown",
            "state": self.state,
            "mode": self.decryption_mode,
            "session_active": self.session_active,
            "retry_count": self.retry_count,
            "transaction_id": self.transaction_id,
        }
