import os
import sys
import time
import json
import socket
import random
import asyncio
import logging
import requests
import nacl.utils
import nacl.encoding

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.onion_crypto import (
    KeyHierarchy,
    trial_peel,
    build_last_mile_block,
    pack_header,
    NONCE_SIZE,
    HEADER_SIZE,
    FRAME_SIZE,
    E2E_BLOCK_SIZE,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

DIRECTORY_URL = os.environ.get("DIRECTORY_URL", "http://directory:5001")
RELAY_IP = os.environ.get("RELAY_IP", "127.0.0.1")
RELAY_PORT = int(os.environ.get("RELAY_PORT", "9001"))

logger.info("Initialising key hierarchy...")
key_hierarchy = KeyHierarchy()
key_hierarchy.initialise()

signing_key = key_hierarchy.signing_key
ed25519_pubkey = bytes(key_hierarchy.verify_key).hex()
x25519_public_key = bytes(key_hierarchy.x25519_public).hex()

seen_nonces = {}
NONCE_TTL = 60
registered_relay_ips = set()


async def nonce_sweeper():
    while True:
        await asyncio.sleep(60)
        now = time.time()
        expired = [n for n, t in seen_nonces.items() if now - t > NONCE_TTL]
        for n in expired:
            del seen_nonces[n]
        logger.info(
            f"Nonce sweep complete. Purged {len(expired)}. Active: {len(seen_nonces)}"
        )


async def register_with_directory():
    while True:
        try:
            payload = {
                "ed25519_pubkey": ed25519_pubkey,
                "x25519_pubkey": x25519_public_key,
                "ip": RELAY_IP,
                "port": RELAY_PORT,
                "timestamp": str(time.time()),
            }
            payload_str = json.dumps(
                payload, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            signature = signing_key.sign(payload_str).signature
            payload["signature"] = nacl.encoding.HexEncoder.encode(signature).decode(
                "utf-8"
            )

            response = await asyncio.to_thread(
                requests.post,
                f"{DIRECTORY_URL}/register_relay",
                json=payload,
                timeout=5,
            )
            if response.status_code == 200:
                logger.info("Successfully registered with Directory API")
                await _refresh_relay_list()
            else:
                logger.warning(f"Registration failed: {response.text}")
        except Exception as e:
            logger.error(f"Error registering with Directory API: {e}")

        await asyncio.sleep(30)


async def _refresh_relay_list():
    try:
        response = await asyncio.to_thread(
            requests.get,
            f"{DIRECTORY_URL}/relays",
            timeout=5,
        )
        if response.status_code == 200:
            data = response.json()
            relay_dict = data.get("relays", {})
            registered_relay_ips.clear()
            for v in relay_dict.values():
                # Bug fix: the directory stores relay IPs as Docker service
                # hostnames (e.g. "relay-1"). Headers carry dotted-decimal IPs
                # produced by socket.inet_ntoa after being packed with
                # gethostbyname in pack_header. Storing the raw hostname in
                # registered_relay_ips means _is_relay("172.18.0.4", 9001)
                # would check against ("relay-1", 9001) and never match —
                # causing every hop to be treated as the last hop. Resolve
                # each hostname to its IP at refresh time so the comparison
                # is always dotted-decimal vs dotted-decimal.
                try:
                    resolved_ip = socket.gethostbyname(v["ip"])
                except socket.gaierror as e:
                    logger.warning(
                        f"Could not resolve relay hostname '{v['ip']}': {e} — skipping"
                    )
                    continue
                registered_relay_ips.add((resolved_ip, int(v["port"])))
            logger.info(
                f"Relay list refreshed: {len(registered_relay_ips)} relays known"
            )
    except Exception as e:
        logger.warning(f"Could not refresh relay list: {e}")


def _is_relay(ip: str, port: int) -> bool:
    return (ip, port) in registered_relay_ips


async def forward_packet(packet: bytes, next_ip: str, next_port: int):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(next_ip, int(next_port)),
            timeout=30.0,
        )
        writer.write(packet)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        logger.info(f"Forwarded {len(packet)}-byte packet to {next_ip}:{next_port}")
    except Exception as e:
        logger.error(f"Failed to forward to {next_ip}:{next_port} — {e}")


async def handle_client(reader, writer):
    client_addr = writer.get_extra_info("peername")
    logger.info(f"Accepted connection from {client_addr}")

    try:
        packet = await asyncio.wait_for(reader.readexactly(FRAME_SIZE), timeout=30.0)

        nonce = packet[:NONCE_SIZE]
        if nonce in seen_nonces:
            logger.warning("Replay attack detected: dropping packet.")
            return
        seen_nonces[nonce] = time.time()

        try:
            header_dict, inner_payload = trial_peel(packet, key_hierarchy)
        except Exception as e:
            logger.warning(
                f"trial_peel failed (not intended recipient or corrupt): {e}"
            )
            return

        next_ip = header_dict["next_ip"]
        next_port = header_dict["next_port"]
        opcode = header_dict["opcode"]

        logger.info(f"Peeled layer. Next hop: {next_ip}:{next_port}")

        delay = random.uniform(0.5, 2.0)
        logger.info(f"Artificial routing delay: {delay:.2f}s")
        await asyncio.sleep(delay)

        if _is_relay(next_ip, next_port):
            # Intermediate hop: forward inner_payload intact — do NOT truncate.
            # inner_payload is the next layer's ciphertext (3808B or 3696B).
            # Frame = [24B new_nonce][64B next_header][Nb inner_payload][padding to 4096]
            new_nonce = nacl.utils.random(NONCE_SIZE)
            next_header = pack_header(
                opcode,
                header_dict["dest_pubkey"],
                next_ip,
                next_port,
            )
            payload_bytes = bytes(inner_payload)
            tail_len = FRAME_SIZE - NONCE_SIZE - HEADER_SIZE - len(payload_bytes)
            if tail_len < 0:
                logger.error(
                    f"inner_payload too large to fit in frame: {len(payload_bytes)}B"
                )
                return
            new_frame = bytearray(
                new_nonce + next_header + payload_bytes + nacl.utils.random(tail_len)
            )
            assert len(new_frame) == FRAME_SIZE
            await forward_packet(bytes(new_frame), next_ip, next_port)

        else:
            # Last hop: deliver last-mile block directly to Bob's client listener.
            e2e_block = bytes(inner_payload[:E2E_BLOCK_SIZE])
            last_mile = build_last_mile_block(e2e_block)
            logger.info(f"Last-hop delivery to Bob at {next_ip}:{next_port}")
            await forward_packet(bytes(last_mile), next_ip, next_port)

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
    asyncio.create_task(nonce_sweeper())
    asyncio.create_task(register_with_directory())
    server = await asyncio.start_server(handle_client, "0.0.0.0", RELAY_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
