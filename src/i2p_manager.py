import asyncio
import aiohttp
import os
import time
import json
import random
import nacl.utils
from pathlib import Path
from src.constants import *
from src.crypto_wrapper import CryptoWrapper
from src.peer_connection import PeerConnection
from src.onion_crypto import NodeDescriptor, Opcode


class I2PManager:
    def __init__(self, crypto_wrapper, ui_queue):
        self.crypto = crypto_wrapper
        self.ui_queue = ui_queue

        self.my_gateway_ip = None
        self.my_gateway_port = None

        self.connections = {}
        self.sack_events = {}
        self.incoming_files = {}
        self.directory_url = os.getenv("DIRECTORY_URL", DIRECTORY_URL)

    async def register_with_directory(self, gateway_ip, gateway_port):
        self.my_gateway_ip = gateway_ip
        self.my_gateway_port = gateway_port

        payload = {
            "ed25519_pubkey": self.crypto.get_ed25519_pubkey(),
            "x25519_pubkey": self.crypto.get_x25519_pubkey(),
            "gateway_ip": gateway_ip,
            "gateway_port": gateway_port,
            "timestamp": str(time.time()),
        }
        payload_str = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        sig = self.crypto.sign(payload_str)
        payload["signature"] = sig.hex()

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.directory_url}/register_leaseset",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        self.ui_queue.put(
                            {"type": "log", "text": "Registered with directory"}
                        )
                        return True
                    else:
                        self.ui_queue.put(
                            {
                                "type": "log",
                                "text": f"Registration failed: {resp.status}",
                            }
                        )
                        return False
            except Exception as e:
                self.ui_queue.put({"type": "log", "text": f"Directory error: {e}"})
                return False

    async def fetch_leaseset(self, peer_ed25519_pubkey):
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.directory_url}/leaseset/{peer_ed25519_pubkey}",
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return None
            except Exception as e:
                self.ui_queue.put(
                    {"type": "log", "text": f"LeaseSet fetch failed: {e}"}
                )
                return None

    async def fetch_relays(self):
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.directory_url}/relays",
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    return {}
            except:
                return {}

    async def _select_circuit(self):
        data = await self.fetch_relays()
        relay_dict = data.get("relays", {})
        relay_list = [
            {
                "x25519_pubkey": v["x25519_pubkey"],
                "ip": v["ip"],
                "port": v["port"],
            }
            for v in relay_dict.values()
        ]
        if len(relay_list) < 3:
            return None
        return random.sample(relay_list, 3)

    def _circuit_to_descriptors(self, circuit):
        return [
            NodeDescriptor(
                ed25519_pubkey=b"\x00" * 32,
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
                ed25519_pubkey=b"\x00" * 32,
                x25519_pubkey=bytes.fromhex(conn.peer_x25519),
                ip=conn.gateway_ip,
                port=conn.gateway_port,
            )
            descriptors = self._circuit_to_descriptors(circuit)

            e2e_block = self.crypto.encrypt_handshake(syn_payload, conn.peer_x25519)
            wire_packet = self.crypto.build_onion_packet(e2e_block, descriptors, dest)
            self.ui_queue.put({"type": "log", "text": "[5/7] Encrypted 3-layer onion"})

            hop1 = circuit[0]
            success = await self._send_packet(wire_packet, hop1["ip"], hop1["port"])
            if not success:
                raise Exception("Failed to send SYN packet")
            self.ui_queue.put(
                {"type": "log", "text": f"[6/7] Sent SYN to relay {hop1['ip']}"}
            )

            self.ui_queue.put(
                {"type": "log", "text": f"[7/7] Awaiting ACK ({HANDSHAKE_TIMEOUT}s)..."}
            )
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

        port_bytes = self.my_gateway_port.to_bytes(4, "big")
        payload[81:85] = port_bytes

        ip_bytes = self.my_gateway_ip.encode("ascii")[:16].ljust(16, b"\x00")
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
                    self.ui_queue.put(
                        {
                            "type": "log",
                            "text": f"Timeout — retry {conn.retry_count + 1}/{MAX_RETRIES}",
                        }
                    )
                    await self.initiate_connection(peer_ed25519)
                else:
                    self.ui_queue.put(
                        {
                            "type": "error",
                            "text": "Handshake failed: max retries exceeded",
                        }
                    )
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

        server = await asyncio.start_server(handle_client, "0.0.0.0", port)
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

        self.ui_queue.put(
            {"type": "log", "text": "Decryption failed for inbound packet"}
        )

    async def _handle_inbound_syn(self, plaintext):
        tx_id = plaintext[1:17].hex()
        alice_ed25519 = plaintext[17:49].hex()
        alice_x25519 = plaintext[49:81].hex()
        alice_port = int.from_bytes(plaintext[81:85], "big")
        alice_ip_raw = plaintext[85:101]
        alice_ip = alice_ip_raw.rstrip(b"\x00").decode("ascii", errors="ignore")

        self.ui_queue.put(
            {"type": "log", "text": f"SYN received from {alice_ed25519[:16]}..."}
        )

        if alice_ed25519 not in self.connections:
            conn = PeerConnection(alice_ed25519, alice_x25519)
            conn.gateway_ip = alice_ip
            conn.gateway_port = alice_port
            self.connections[alice_ed25519] = conn
        else:
            conn = self.connections[alice_ed25519]
            conn.peer_x25519 = alice_x25519
            conn.gateway_ip = alice_ip
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
        opcode = plaintext[0]
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
            text = payload.decode("utf-8", errors="ignore").rstrip("\x00")
            self.ui_queue.put(
                {"type": "message", "peer": conn.peer_ed25519, "text": text}
            )

        elif opcode == Opcode.FILE:
            await self._handle_file_chunk(payload, conn)

        elif opcode == Opcode.SACK:
            self._handle_sack(payload)

    async def _send_ack(self, conn):
        circuit = await self._select_circuit()
        if not circuit:
            self.ui_queue.put(
                {"type": "error", "text": "Cannot send ACK: no relays available"}
            )
            return

        conn.set_circuit_responder(circuit)

        ack_payload = bytearray(E2E_PLAINTEXT_SIZE)
        ack_payload[0] = Opcode.ACK

        my_x25519 = bytes.fromhex(self.crypto.get_x25519_pubkey())
        ack_payload[1:33] = my_x25519

        dest = NodeDescriptor(
            ed25519_pubkey=b"\x00" * 32,
            x25519_pubkey=bytes.fromhex(conn.peer_x25519),
            ip=conn.gateway_ip,
            port=conn.gateway_port,
        )
        descriptors = self._circuit_to_descriptors(circuit)

        e2e_block = self.crypto.encrypt_handshake(bytes(ack_payload), conn.peer_x25519)
        wire_packet = self.crypto.build_onion_packet(e2e_block, descriptors, dest)

        await self._send_packet(wire_packet, circuit[0]["ip"], circuit[0]["port"])

        conn.upgrade_to_session()
        self.crypto.establish_session(conn.peer_x25519)
        self.ui_queue.put(
            {"type": "log", "text": f"ACK sent to {conn.peer_ed25519[:16]}..."}
        )

    async def send_chat_message(self, text: str, peer_ed25519: str):
        conn = self.connections.get(peer_ed25519)
        if not conn or not conn.is_active():
            self.ui_queue.put({"type": "error", "text": "No active session with peer"})
            return

        payload = bytearray(E2E_PLAINTEXT_SIZE)
        payload[0] = Opcode.CHAT
        encoded = text.encode("utf-8")[: E2E_PLAINTEXT_SIZE - 1]
        payload[1 : 1 + len(encoded)] = encoded

        dest = NodeDescriptor(
            ed25519_pubkey=b"\x00" * 32,
            x25519_pubkey=bytes.fromhex(conn.peer_x25519),
            ip=conn.gateway_ip,
            port=conn.gateway_port,
        )
        descriptors = self._circuit_to_descriptors(conn.circuit)

        e2e_block = self.crypto.encrypt_session(bytes(payload), conn.peer_x25519)
        wire_packet = self.crypto.build_onion_packet(e2e_block, descriptors, dest)

        await self._send_packet(
            wire_packet, conn.circuit[0]["ip"], conn.circuit[0]["port"]
        )

    # FILE_CHUNK_HEADER layout (91 bytes after opcode stripped by caller):
    #   [0:16]  tx_id
    #   [16:20] chunk_num uint32
    #   [20:24] total_chunks uint32
    #   [24:26] data_len uint16
    #   [26:90] filename (64 bytes, null-padded)
    #   [90:]   data (up to E2E_PLAINTEXT_SIZE - 91 = 3493 bytes)
    _FILE_DATA_SIZE = E2E_PLAINTEXT_SIZE - 91

    async def send_file(self, filepath: str, peer_ed25519: str):
        conn = self.connections.get(peer_ed25519)
        if not conn or not conn.is_active():
            self.ui_queue.put({"type": "error", "text": "No active session with peer"})
            return

        path = Path(filepath)
        if not path.exists():
            self.ui_queue.put({"type": "error", "text": f"File not found: {filepath}"})
            return

        data = path.read_bytes()
        tx_id = nacl.utils.random(16)
        tx_id_hex = tx_id.hex()

        chunk_size = self._FILE_DATA_SIZE
        chunks = [
            data[i : i + chunk_size] for i in range(0, max(len(data), 1), chunk_size)
        ]
        total_chunks = len(chunks)

        fname_raw = path.name.encode("utf-8", errors="replace")[:64]
        fname_padded = fname_raw.ljust(64, b"\x00")

        dest = NodeDescriptor(
            ed25519_pubkey=b"\x00" * 32,
            x25519_pubkey=bytes.fromhex(conn.peer_x25519),
            ip=conn.gateway_ip,
            port=conn.gateway_port,
        )
        descriptors = self._circuit_to_descriptors(conn.circuit)

        self.ui_queue.put(
            {
                "type": "log",
                "text": f"[FILE] Sending {path.name} ({total_chunks} chunks)",
            }
        )

        for chunk_num, chunk_data in enumerate(chunks):
            payload = bytearray(E2E_PLAINTEXT_SIZE)
            payload[0] = Opcode.FILE
            payload[1:17] = tx_id
            payload[17:21] = chunk_num.to_bytes(4, "big")
            payload[21:25] = total_chunks.to_bytes(4, "big")
            payload[25:27] = len(chunk_data).to_bytes(2, "big")
            payload[27:91] = fname_padded
            payload[91 : 91 + len(chunk_data)] = chunk_data

            e2e_block = self.crypto.encrypt_session(bytes(payload), conn.peer_x25519)
            wire_packet = self.crypto.build_onion_packet(e2e_block, descriptors, dest)
            await self._send_packet(
                wire_packet, conn.circuit[0]["ip"], conn.circuit[0]["port"]
            )

            is_batch_boundary = (chunk_num + 1) % BATCH_SIZE == 0
            is_last_chunk = (chunk_num + 1) == total_chunks

            if is_batch_boundary or is_last_chunk:
                batch_num = chunk_num // BATCH_SIZE + 1
                self.ui_queue.put(
                    {"type": "log", "text": f"[FILE] Waiting SACK batch {batch_num}..."}
                )
                acked = await self._wait_for_sack(
                    tx_id_hex, batch_num, FILE_BATCH_TIMEOUT
                )
                if not acked:
                    self.ui_queue.put(
                        {
                            "type": "error",
                            "text": f"File transfer failed: batch {batch_num} timeout",
                        }
                    )
                    return

            await asyncio.sleep(0)

        self.ui_queue.put(
            {"type": "log", "text": f"[FILE] {path.name} sent successfully"}
        )

    async def _wait_for_sack(
        self, tx_id_hex: str, batch_num: int, timeout: float
    ) -> bool:
        key = (tx_id_hex, batch_num)
        event = asyncio.Event()
        self.sack_events[key] = event
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False
        finally:
            self.sack_events.pop(key, None)

    def _handle_sack(self, payload):
        tx_id_hex = payload[0:16].hex()
        batch_num = int.from_bytes(payload[16:20], "big")
        key = (tx_id_hex, batch_num)
        event = self.sack_events.get(key)
        if event:
            event.set()
        self.ui_queue.put(
            {"type": "log", "text": f"[SACK] Batch {batch_num} acknowledged"}
        )

    async def _send_sack(self, tx_id_hex: str, batch_num: int, conn):
        payload = bytearray(E2E_PLAINTEXT_SIZE)
        payload[0] = Opcode.SACK
        payload[1:17] = bytes.fromhex(tx_id_hex)
        payload[17:21] = batch_num.to_bytes(4, "big")

        dest = NodeDescriptor(
            ed25519_pubkey=b"\x00" * 32,
            x25519_pubkey=bytes.fromhex(conn.peer_x25519),
            ip=conn.gateway_ip,
            port=conn.gateway_port,
        )
        descriptors = self._circuit_to_descriptors(conn.circuit)

        e2e_block = self.crypto.encrypt_session(bytes(payload), conn.peer_x25519)
        wire_packet = self.crypto.build_onion_packet(e2e_block, descriptors, dest)
        await self._send_packet(
            wire_packet, conn.circuit[0]["ip"], conn.circuit[0]["port"]
        )

    async def _handle_file_chunk(self, payload, conn):
        tx_id_hex = payload[0:16].hex()
        chunk_num = int.from_bytes(payload[16:20], "big")
        total_chunks = int.from_bytes(payload[20:24], "big")
        data_len = int.from_bytes(payload[24:26], "big")
        filename = payload[26:90].rstrip(b"\x00").decode("utf-8", errors="replace")
        chunk_data = bytes(payload[90 : 90 + data_len])

        if tx_id_hex not in self.incoming_files:
            self.incoming_files[tx_id_hex] = {
                "filename": filename,
                "total_chunks": total_chunks,
                "chunks": {},
            }

        self.incoming_files[tx_id_hex]["chunks"][chunk_num] = chunk_data

        is_batch_boundary = (chunk_num + 1) % BATCH_SIZE == 0
        is_last_chunk = (chunk_num + 1) == total_chunks

        if is_batch_boundary or is_last_chunk:
            batch_num = chunk_num // BATCH_SIZE + 1
            await self._send_sack(tx_id_hex, batch_num, conn)

        if is_last_chunk:
            file_info = self.incoming_files.pop(tx_id_hex)
            chunks_map = file_info["chunks"]
            file_data = b"".join(chunks_map[i] for i in range(total_chunks))

            save_dir = Path("received_files")
            save_dir.mkdir(parents=True, exist_ok=True)
            save_path = save_dir / file_info["filename"]
            save_path.write_bytes(file_data)

            self.ui_queue.put(
                {
                    "type": "file_received",
                    "filename": file_info["filename"],
                    "path": str(save_path),
                    "size": len(file_data),
                }
            )
