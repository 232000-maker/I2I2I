import time
import json
import logging
from flask import Flask, request, jsonify
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
import nacl.encoding

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

# In-memory stateless registry
relays = {}
leasesets = {}
rate_limits = {}

# Constants
EXPIRY_SECONDS = 60
RATE_LIMIT_SECONDS = 5
MAX_JITTER_SECONDS = 10

def purge_expired():
    now = time.time()
    expired_relays = [k for k, v in relays.items() if now - v["last_seen"] > EXPIRY_SECONDS]
    for k in expired_relays:
        del relays[k]
        
    expired_leasesets = [k for k, v in leasesets.items() if now - v["last_seen"] > EXPIRY_SECONDS]
    for k in expired_leasesets:
        del leasesets[k]

def verify_payload(payload):
    """
    Validates timestamp jitter, rate limiting, and ed25519 signature.
    """
    if "timestamp" not in payload or "signature" not in payload or "ed25519_pubkey" not in payload:
        return False, "Missing timestamp, signature, or pubkey"

    now = time.time()
    try:
        timestamp = float(payload["timestamp"])
    except ValueError:
        return False, "Invalid timestamp"

    # 1. Timestamp Jitter
    if abs(now - timestamp) > MAX_JITTER_SECONDS:
        return False, "Timestamp jitter too large"

    pubkey_hex = payload["ed25519_pubkey"]

    # 2. Rate Limiting
    last_seen = rate_limits.get(pubkey_hex, 0)
    if now - last_seen < RATE_LIMIT_SECONDS:
        return False, "Rate limited"
    rate_limits[pubkey_hex] = now

    # 3. Signature Verification
    signature_hex = payload.pop("signature")
    
    # We serialize the payload (without signature) with sorted keys to verify
    payload_str = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
    
    try:
        verify_key = VerifyKey(pubkey_hex, encoder=nacl.encoding.HexEncoder)
        signature_bytes = nacl.encoding.HexEncoder.decode(signature_hex)
        verify_key.verify(payload_str, signature_bytes)
    except BadSignatureError:
        return False, "Invalid signature"
    except Exception as e:
        return False, f"Signature validation error: {str(e)}"
        
    # Re-insert signature for completeness if needed elsewhere
    payload["signature"] = signature_hex
    return True, ""


@app.route("/register_relay", methods=["POST"])
def register_relay():
    purge_expired()
    payload = request.json
    if not payload:
        return jsonify({"error": "No payload"}), 400

    required_fields = ["ed25519_pubkey", "x25519_pubkey", "ip", "port", "timestamp", "signature"]
    if not all(k in payload for k in required_fields):
        return jsonify({"error": "Missing relay fields"}), 400

    valid, msg = verify_payload(payload.copy())
    if not valid:
        return jsonify({"error": msg}), 403

    pubkey = payload["ed25519_pubkey"]
    relays[pubkey] = {
        "x25519_pubkey": payload["x25519_pubkey"],
        "ip": payload["ip"],
        "port": payload["port"],
        "last_seen": time.time()
    }
    
    logger.info(f"Registered Relay: {pubkey[:8]}... at {payload['ip']}:{payload['port']}")
    return jsonify({"status": "ok"}), 200

@app.route("/register_leaseset", methods=["POST"])
def register_leaseset():
    purge_expired()
    payload = request.json
    if not payload:
        return jsonify({"error": "No payload"}), 400

    required_fields = ["ed25519_pubkey", "x25519_pubkey", "gateway_ip", "gateway_port", "timestamp", "signature"]
    if not all(k in payload for k in required_fields):
        return jsonify({"error": "Missing leaseset fields"}), 400

    valid, msg = verify_payload(payload.copy())
    if not valid:
        return jsonify({"error": msg}), 403

    pubkey = payload["ed25519_pubkey"]
    leasesets[pubkey] = {
        "x25519_pubkey": payload["x25519_pubkey"],
        "gateway_ip": payload["gateway_ip"],
        "gateway_port": payload["gateway_port"],
        "last_seen": time.time()
    }
    
    logger.info(f"Registered LeaseSet: {pubkey[:8]}... via gateway {payload['gateway_ip']}:{payload['gateway_port']}")
    return jsonify({"status": "ok"}), 200

@app.route("/relays", methods=["GET"])
def get_relays():
    purge_expired()
    return jsonify({"relays": relays}), 200

@app.route("/leaseset/<pubkey>", methods=["GET"])
def get_leaseset(pubkey):
    purge_expired()
    if pubkey in leasesets:
        return jsonify(leasesets[pubkey]), 200
    return jsonify({"error": "Not found"}), 404

if __name__ == "__main__":
    logger.info("Starting Stateless Directory Server...")
    app.run(host="0.0.0.0", port=5001)
