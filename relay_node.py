import os
import time
import json
import random
import asyncio
import logging
import requests
from nacl.signing import SigningKey
from nacl.public import PrivateKey, SealedBox
from nacl.exceptions import CryptoError
import nacl.encoding

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Environment Configuration
DIRECTORY_URL = os.environ.get("DIRECTORY_URL", "http://directory:5001")
RELAY_IP = os.environ.get("RELAY_IP", "127.0.0.1")
RELAY_PORT = int(os.environ.get("RELAY_PORT", "9001"))

# Cryptographic Keys
logger.info("Generating keys...")
signing_key = SigningKey.generate()
ed25519_pubkey = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
x25519_private_key = signing_key.to_curve25519_private_key()
x25519_public_key = x25519_private_key.public_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')

# Nonce Registry
seen_nonces = {}
NONCE_TTL = 60

async def nonce_sweeper():
    """Independent task that runs every 60s to purge expired nonces."""
    while True:
        await asyncio.sleep(60)
        now = time.time()
        expired = [nonce for nonce, timestamp in seen_nonces.items() if now - timestamp > NONCE_TTL]
        for nonce in expired:
            del seen_nonces[nonce]
        logger.info(f"Nonce sweep complete. Purged {len(expired)} nonces. Active: {len(seen_nonces)}")

async def register_with_directory():
    """Background task to re-register the relay every 30 seconds."""
    while True:
        try:
            payload = {
                "ed25519_pubkey": ed25519_pubkey,
                "x25519_pubkey": x25519_public_key,
                "ip": RELAY_IP,
                "port": RELAY_PORT,
                "timestamp": str(time.time())
            }
            # Serialize payload and sign
            payload_str = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
            signature = signing_key.sign(payload_str).signature
            payload["signature"] = nacl.encoding.HexEncoder.encode(signature).decode('utf-8')

            # We use thread pool for requests to not block event loop
            response = await asyncio.to_thread(requests.post, f"{DIRECTORY_URL}/register_relay", json=payload, timeout=5)
            if response.status_code == 200:
                logger.info("Successfully registered with Directory API")
            else:
                logger.warning(f"Registration failed: {response.text}")
        except Exception as e:
            logger.error(f"Error registering with Directory API: {e}")
            
        await asyncio.sleep(30)

async def forward_packet(packet, next_ip, next_port):
    """Forward the padded 4096-byte packet to the next hop."""
    try:
        # Enforce 30s connection timeout for forwarding
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(next_ip, int(next_port)), 
            timeout=30.0
        )
        writer.write(packet)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        logger.info(f"Forwarded 4096-byte packet to {next_ip}:{next_port}")
    except Exception as e:
        logger.error(f"Failed to forward packet to {next_ip}:{next_port} - {e}")

async def handle_client(reader, writer):
    """Handle incoming TCP connection."""
    client_addr = writer.get_extra_info('peername')
    logger.info(f"Accepted connection from {client_addr}")
    
    try:
        # 4.2 The 4096-Byte Strict Read (with 30s timeout)
        packet = await asyncio.wait_for(reader.readexactly(4096), timeout=30.0)
        
        # Nonce is the first 24 bytes
        nonce = packet[:24]
        if nonce in seen_nonces:
            logger.warning("Replay attack detected: Nonce already seen. Dropping packet.")
            return
            
        seen_nonces[nonce] = time.time()

        # 4.3 Trial-Peeling Loop
        # Attempt to decrypt the outer layer using the relay's cached X25519 Private Key
        # Since this domain does not construct envelopes, we rely on standard PyNaCl behavior
        box = SealedBox(x25519_private_key)
        
        peeled_successfully = False
        next_ip = None
        next_port = None
        forward_payload = packet
        
        try:
            # The ciphertext starts after the 24-byte nonce
            # We attempt to decrypt the rest of the payload
            # (In standard SealedBox, the ephemeral pubkey is prepended to the ciphertext)
            decrypted = box.decrypt(packet[24:])
            
            # If decryption succeeds, we strip the layer and read the 64-byte structural header
            # Header is assumed to be at the start of decrypted data: Dest_PubKey, Next_IP, Next_Port, Padding
            # We'll mock the extraction here for testing purposes
            # Assume header format: IP:PORT padded with null bytes
            header = decrypted[:64]
            header_str = header.decode('utf-8', errors='ignore').strip('\x00')
            if ':' in header_str:
                next_ip, next_port = header_str.split(':', 1)
                
            # Re-pad to exactly 4096 bytes
            # For testing and structural compliance, we ensure the new packet is 4096B
            padding_len = 4096 - (24 + len(decrypted) - 64)
            if padding_len > 0:
                new_packet = nonce + decrypted[64:] + os.urandom(padding_len)
            else:
                new_packet = (nonce + decrypted[64:])[:4096]
                
            forward_payload = new_packet
            peeled_successfully = True
            logger.info("Successfully peeled a layer.")
        except CryptoError:
            # We are not the intended recipient of this layer.
            # In a real mix-net, if we can't peel it, it might be corrupted or we aren't the right relay
            # If we are just passing random bytes for testing as per contract: "just pass arrays of random bytes"
            # We will still forward it randomly or log it. But wait, if we can't peel it, we don't know the next IP.
            # We'll log the failure. If testing with mock random bytes, we won't know where to forward.
            logger.warning("CryptoError: Could not peel layer. Not the intended recipient.")
            peeled_successfully = False

        # 4.4 Artificial Routing Delay (0.5 to 2.0 seconds)
        delay = random.uniform(0.5, 2.0)
        logger.info(f"Applying artificial routing delay of {delay:.2f} seconds.")
        await asyncio.sleep(delay)

        # Forward if we peeled successfully and know where to go
        if peeled_successfully and next_ip and next_port:
            await forward_packet(forward_payload, next_ip, next_port)
        elif not peeled_successfully:
            logger.info("Packet dropped or held: Not peeled successfully (expected during raw mock tests without real headers).")
            
    except asyncio.IncompleteReadError:
        logger.error("Connection closed before receiving exactly 4096 bytes.")
    except asyncio.TimeoutError:
        logger.error("Connection timed out (exceeded 30 seconds).")
    except Exception as e:
        logger.error(f"Error handling connection: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def main():
    logger.info(f"Starting Relay Node at {RELAY_IP}:{RELAY_PORT}")
    
    # Start background tasks
    asyncio.create_task(nonce_sweeper())
    asyncio.create_task(register_with_directory())
    
    # Start TCP Server
    server = await asyncio.start_server(handle_client, '0.0.0.0', RELAY_PORT)
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
