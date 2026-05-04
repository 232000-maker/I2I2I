import asyncio
import aiohttp
import os
import time
import json
import random
import nacl.utils
from src.constants import *
from src.crypto_wrapper import CryptoWrapper
from src.peer_connection import PeerConnection
from src.onion_crypto import NodeDescriptor, Opcode


class I2PManager:
    def __init__(self, crypto_wrapper, ui_queue):
        self.crypto    = crypto_wrapper
        self.ui_queue  = ui_queue

        self.my_gateway_ip   = None
        self.my_gateway_port = None

        self.connections   = {}
        self.directory_url = os.getenv("DIRECTORY_URL", DIRECTORY_URL)

    async def register_with_directory(self, gateway_ip, gateway_port):
        self.my_gateway_ip   = gateway_ip
        self.my_gateway_port = gateway_port

        payload = {
            "ed25519_pubkey": self.crypto.get_ed25519_pubkey(),
            "x25519_pubkey":  self.crypto.get_x25519_pubkey(),
            "gateway_ip":     gateway_ip,
            "gateway_port":   gateway_port,
            "timestamp":      str(time.time()),
        }
        payload_str = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
        sig = self.crypto.sign(payload_str)
        payload["signature"] = sig.hex()

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.directory_url}/register_leaseset",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        self.ui_queue.put({"type": "log", "text": "Registered with directory"})
                        return True
                    else:
                        self.ui_queue.put({"type": "log", "text": f"Registration failed: {resp.status}"})
                        return False
            except Exception as e:
                self.ui_queue.put({"type": "log", "text": f"Directory error: {e}"})
                return False

    async def fetch_leaseset(self, peer_ed25519_pubkey):
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.directory_url}/leaseset/{peer_ed25519_pubkey}",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return None
            except Exception as e:
                self.ui_queue.put({"type": "log", "text": f"LeaseSet fetch failed: {e}"})
                return None

    async def fetch_relays(self):
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.directory_url}/relays",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return {}
            except:
                return {}

    async def _select_circuit(self):
        data       = await self.fetch_relays()
        relay_dict = data.get("relays", {})
        relay_list = [
            {
                "x25519_pubkey": v["x25519_pubkey"],
                "ip":            v["ip"],
                "port":          v["port"],
            }
            for v in relay_dict.values()
        ]
        if len(relay_list) < 3:
            return None
        return random.sample(relay_list, 3)

    def _circuit_to_descriptors(self, circuit):
        return [
            NodeDescriptor(
                ed25519_pubkey=b'\x00' * 32,
                x25519_pubkey=bytes.fromhex(r["x25519_pubkey"]),
                ip=r["ip"],
                port=r["port"],
            )
            for r in circuit
        ]

    async def initiate_connection(self, peer_ed25519_pubkey):
        try:
            if peer_ed25519_pubkey in self.connections:
                conn = self.connections[peer_ed25519_pubkey]
            else:
                conn = PeerConnection(peer_ed25519_pubkey)
                self.connections[peer_ed25519_pubkey] = conn

            tx_id = conn.initiate_handshake()
            self.ui_queue.put({"type": "log", "text": f"[1/7] TX ID: {tx_id[:8]}..."})

            circuit = await self._select_circuit()
            if not circuit:
                raise Exception("No relays available")

            conn.set_circuit(circuit)
            self.ui_queue.put({"type": "log", "text": "[2/7] Selected 3-hop circuit"})

            leaseset = await self.fetch_leaseset(peer_ed25519_pubkey)
            if not leaseset:
                raise Exception("Peer LeaseSet not found")

            conn.set_leaseset(leaseset)
            self.ui_queue.put({"type": "log", "text": "[3/7] Retrieved peer LeaseSet"})

            syn_payload = self._build_syn_packet(tx_id)
            self.ui_queue.put({"type": "log", "text": "[4/7] Built SYN packet"})

            dest = NodeDescriptor(
                ed25519_pubkey=b'\x00' * 32,
                x25519_pubkey=bytes.fromhex(conn.peer_x25519),
                ip=conn.gateway_ip,
                port=conn.gateway_port,
            )
            descriptors = self._circuit_to_descriptors(circuit)

            e2e_block   = self.crypto.encrypt_handshake(syn_payload, conn.peer_x25519)
            wire_packet = self.crypto.build_onion_packet(e2e_block, descriptors, dest)
            self.ui_queue.put({"type": "log", "text": "[5/7] Encrypted 3-layer onion"})

            hop1 = circuit[0]
            success = await self._send_packet(wire_packet, hop1["ip"], hop1["port"])
            if not success:
                raise Exception("Failed to send SYN packet")
            self.ui_queue.put({"type": "log", "text": f"[6/7] Sent SYN to relay {hop1['ip']}"})

            self.ui_queue.put({"type": "log", "text": f"[7/7] Awaiting ACK ({HANDSHAKE_TIMEOUT}s)..."})
            asyncio.create_task(self._monitor_handshake_timeout(peer_ed25519_pubkey))

        except Exception as e:
            self.ui_queue.put({"type": "error", "text": f"Handshake failed: {e}"})
            self.connections.pop(peer_ed25519_pubkey, None)

    def _build_syn_packet(self, tx_id):
        payload = bytearray(E2E_PLAINTEXT_SIZE)
        payload[0] = Opcode.SYN

        tx_bytes = bytes.fromhex(tx_id)
        payload[1:17] = tx_bytes

        my_ed25519 = bytes.fromhex(self.crypto.get_ed25519_pubkey())
        payload[17:49] = my_ed25519

        my_x25519 = bytes.fromhex(self.crypto.get_x25519_pubkey())
        payload[49:81] = my_x25519

        port_bytes = self.my_gateway_port.to_bytes(4, 'big')
        payload[81:85] = port_bytes

        ip_bytes = self.my_gateway_ip.encode('ascii')[:16].ljust(16, b'\x00')
        payload[85:101] = ip_bytes

        return bytes(payload)

    async def _monitor_handshake_timeout(self, peer_ed25519):
        conn = self.connections.get(peer_ed25519)
        if not conn:
            return

        while conn.state in (STATE_AWAITING_CIRCUIT, STATE_AWAITING_ACK):
            await asyncio.sleep(1)
            if conn.check_timeout():
                if conn.can_retry():
                    self.ui_queue.put({"type": "log", "text": f"Timeout — retry {conn.retry_count + 1}/{MAX_RETRIES}"})
                    await self.initiate_connection(peer_ed25519)
                else:
                    self.ui_queue.put({"type": "error", "text": "Handshake failed: max retries exceeded"})
                    self.connections.pop(peer_ed25519, None)
                break

    async def _send_packet(self, packet, ip, port):
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            writer.write(bytes(packet))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return True
        except Exception as e:
            self.ui_queue.put({"type": "log", "text": f"Send failed: {e}"})
            return False

    async def listen_for_packets(self, port):
        async def handle_client(reader, writer):
            try:
                packet = await reader.readexactly(FRAME_SIZE)
                await self._process_inbound_packet(packet)
            except:
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle_client, '0.0.0.0', port)
        self.ui_queue.put({"type": "log", "text": f"Listening on port {port}"})
        async with server:
            await server.serve_forever()

    async def _process_inbound_packet(self, packet):
        e2e_block = packet[:E2E_BLOCK_SIZE]

        try:
            decrypted = self.crypto.decrypt_handshake(e2e_block)
            opcode = decrypted[0]
            if opcode == Opcode.SYN:
                await self._handle_inbound_syn(decrypted)
                return
            elif opcode == Opcode.ACK:
                self._handle_inbound_ack_unknown(decrypted)
                return
        except Exception:
            pass

        for peer_ed25519, conn in list(self.connections.items()):
            try:
                mode = conn.get_decryption_mode()
                if mode == MODE_SESSION:
                    decrypted = self.crypto.decrypt_session(e2e_block, conn.peer_x25519)
                else:
                    decrypted = self.crypto.decrypt_handshake(e2e_block)

                await self._handle_decrypted_message(decrypted, conn)
                return
            except Exception:
                continue

        self.ui_queue.put({"type": "log", "text": "Decryption failed for inbound packet"})

    async def _handle_inbound_syn(self, plaintext):
        tx_id         = plaintext[1:17].hex()
        alice_ed25519 = plaintext[17:49].hex()
        alice_x25519  = plaintext[49:81].hex()
        alice_port    = int.from_bytes(plaintext[81:85], 'big')
        alice_ip_raw  = plaintext[85:101]
        alice_ip      = alice_ip_raw.rstrip(b'\x00').decode('ascii', errors='ignore')

        self.ui_queue.put({"type": "log", "text": f"SYN received from {alice_ed25519[:16]}..."})

        if alice_ed25519 not in self.connections:
            conn = PeerConnection(alice_ed25519, alice_x25519)
            conn.gateway_ip   = alice_ip
            conn.gateway_port = alice_port
            self.connections[alice_ed25519] = conn
        else:
            conn = self.connections[alice_ed25519]
            conn.peer_x25519  = alice_x25519
            conn.gateway_ip   = alice_ip
            conn.gateway_port = alice_port

        await self._send_ack(conn)

    def _handle_inbound_ack_unknown(self, plaintext):
        for peer_ed25519, conn in list(self.connections.items()):
            if conn.state == STATE_AWAITING_ACK:
                conn.receive_ack()
                self.crypto.establish_session(conn.peer_x25519)
                self.ui_queue.put({"type": "ack", "peer": peer_ed25519})
                return

    async def _handle_decrypted_message(self, plaintext, conn):
        opcode  = plaintext[0]
        payload = plaintext[1:]

        conn.update_activity()

        if opcode == Opcode.SYN:
            await self._send_ack(conn)

        elif opcode == Opcode.ACK:
            if conn.state == STATE_AWAITING_ACK:
                conn.receive_ack()
            else:
                conn.upgrade_to_session()
            self.crypto.establish_session(conn.peer_x25519)
            self.ui_queue.put({"type": "ack", "peer": conn.peer_ed25519})

        elif opcode == Opcode.CHAT:
            text = payload.decode('utf-8', errors='ignore').rstrip('\x00')
            self.ui_queue.put({"type": "message", "peer": conn.peer_ed25519, "text": text})

    async def _send_ack(self, conn):
        circuit = await self._select_circuit()
        if not circuit:
            self.ui_queue.put({"type": "error", "text": "Cannot send ACK: no relays available"})
            return

        conn.set_circuit_responder(circuit)

        ack_payload = bytearray(E2E_PLAINTEXT_SIZE)
        ack_payload[0] = Opcode.ACK

        my_x25519 = bytes.fromhex(self.crypto.get_x25519_pubkey())
        ack_payload[1:33] = my_x25519

        dest = NodeDescriptor(
            ed25519_pubkey=b'\x00' * 32,
            x25519_pubkey=bytes.fromhex(conn.peer_x25519),
            ip=conn.gateway_ip,
            port=conn.gateway_port,
        )
        descriptors = self._circuit_to_descriptors(circuit)

        e2e_block   = self.crypto.encrypt_handshake(bytes(ack_payload), conn.peer_x25519)
        wire_packet = self.crypto.build_onion_packet(e2e_block, descriptors, dest)

        await self._send_packet(wire_packet, circuit[0]["ip"], circuit[0]["port"])

        conn.upgrade_to_session()
        self.crypto.establish_session(conn.peer_x25519)
        self.ui_queue.put({"type": "log", "text": f"ACK sent to {conn.peer_ed25519[:16]}..."})

    async def send_chat_message(self, text: str, peer_ed25519: str):
        conn = self.connections.get(peer_ed25519)
        if not conn or not conn.is_active():
            self.ui_queue.put({"type": "error", "text": "No active session with peer"})
            return

        payload = bytearray(E2E_PLAINTEXT_SIZE)
        payload[0] = Opcode.CHAT
        encoded = text.encode('utf-8')[:E2E_PLAINTEXT_SIZE - 1]
        payload[1:1 + len(encoded)] = encoded

        dest = NodeDescriptor(
            ed25519_pubkey=b'\x00' * 32,
            x25519_pubkey=bytes.fromhex(conn.peer_x25519),
            ip=conn.gateway_ip,
            port=conn.gateway_port,
        )
        descriptors = self._circuit_to_descriptors(conn.circuit)

        e2e_block   = self.crypto.encrypt_session(bytes(payload), conn.peer_x25519)
        wire_packet = self.crypto.build_onion_packet(e2e_block, descriptors, dest)

        await self._send_packet(wire_packet, conn.circuit[0]["ip"], conn.circuit[0]["port"])
