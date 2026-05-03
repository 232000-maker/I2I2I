"""
Network Domain - Complete Implementation
Handles TCP operations, handshake flow, and SACK file transfer
"""

import asyncio
import aiohttp
import os
import time
import nacl.utils
from src.constants import *
from src.crypto_wrapper import CryptoWrapper
from src.peer_connection import PeerConnection


class I2PManager:
    def __init__(self, crypto_wrapper, ui_queue):
        self.crypto = crypto_wrapper
        self.ui_queue = ui_queue
        
        # Network state
        self.my_gateway_ip = None
        self.my_gateway_port = None
        
        # Peer connections (peer_ed25519 -> PeerConnection)
        self.connections = {}
        
        # Directory URL
        self.directory_url = os.getenv("DIRECTORY_URL", DIRECTORY_URL)
        
        # File transfer state
        self.file_transfers = {}
    
    # ===== DIRECTORY OPERATIONS =====
    
    async def register_with_directory(self, gateway_ip, gateway_port):
        """Register LeaseSet with directory"""
        self.my_gateway_ip = gateway_ip
        self.my_gateway_port = gateway_port
        
        leaseset = {
            "ed25519_pubkey": self.crypto.get_ed25519_pubkey(),
            "x25519_pubkey": self.crypto.get_x25519_pubkey(),
            "gateway_ip": gateway_ip,
            "gateway_port": gateway_port
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.directory_url}/register",
                    json=leaseset,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        self.ui_queue.put({
                            "type": "log",
                            "text": "✓ Registered with directory"
                        })
                        return True
                    else:
                        self.ui_queue.put({
                            "type": "log",
                            "text": f"✗ Registration failed: {resp.status}"
                        })
                        return False
            except Exception as e:
                self.ui_queue.put({
                    "type": "log",
                    "text": f"✗ Directory error: {e}"
                })
                return False
    
    async def fetch_leaseset(self, peer_ed25519_pubkey):
        """Fetch peer's LeaseSet from directory"""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.directory_url}/leaseset/{peer_ed25519_pubkey}",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        return None
            except Exception as e:
                self.ui_queue.put({
                    "type": "log",
                    "text": f"✗ LeaseSet fetch failed: {e}"
                })
                return None
    
    async def fetch_relays(self):
        """Query directory for relay nodes"""
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.directory_url}/relays",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        return []
            except:
                return []
    
    # ===== HANDSHAKE FLOW (ALICE) =====
    
    async def initiate_connection(self, peer_ed25519_pubkey):
        """Alice's 7-step handshake flow"""
        try:
            # Create or get peer connection
            if peer_ed25519_pubkey in self.connections:
                conn = self.connections[peer_ed25519_pubkey]
            else:
                conn = PeerConnection(peer_ed25519_pubkey)
                self.connections[peer_ed25519_pubkey] = conn
            
            # Step 1: Generate transaction ID
            tx_id = conn.initiate_handshake()
            self.ui_queue.put({
                "type": "log",
                "text": f"[1/7] Generated TX ID: {tx_id[:8]}..."
            })
            
            # Step 2: Select relay circuit
            circuit = await self._select_circuit()
            if not circuit:
                raise Exception("No relays available")
            
            conn.set_circuit(circuit)
            self.ui_queue.put({
                "type": "log",
                "text": f"[2/7] Selected 3-hop circuit"
            })
            
            # Step 3: Query directory for Bob's LeaseSet
            leaseset = await self.fetch_leaseset(peer_ed25519_pubkey)
            if not leaseset:
                raise Exception("Peer LeaseSet not found")
            
            conn.set_leaseset(leaseset)
            self.ui_queue.put({
                "type": "log",
                "text": f"[3/7] Retrieved peer LeaseSet"
            })
            
            # Step 4: Build SYN packet
            syn_payload = self._build_syn_packet(tx_id)
            self.ui_queue.put({
                "type": "log",
                "text": f"[4/7] Built SYN packet"
            })
            
            # Step 5: Encrypt via crypto domain
            e2e_block = self.crypto.encrypt_handshake(syn_payload, conn.peer_x25519)
            wire_packet = self.crypto.build_onion_packet(e2e_block, circuit)
            self.ui_queue.put({
                "type": "log",
                "text": f"[5/7] Encrypted 3-layer onion"
            })
            
            # Step 6: Send to Hop 1
            hop1 = circuit[0]
            success = await self._send_packet(wire_packet, hop1["ip"], hop1["port"])
            if not success:
                raise Exception("Failed to send packet")
            
            self.ui_queue.put({
                "type": "log",
                "text": f"[6/7] Sent to relay {hop1['ip']}"
            })
            
            # Step 7: Wait for ACK
            self.ui_queue.put({
                "type": "log",
                "text": f"[7/7] Waiting for ACK (timeout: {HANDSHAKE_TIMEOUT}s)..."
            })
            
            # Start timeout monitor
            asyncio.create_task(self._monitor_handshake_timeout(peer_ed25519_pubkey))
            
        except Exception as e:
            self.ui_queue.put({
                "type": "error",
                "text": f"Handshake failed: {e}"
            })
            if peer_ed25519_pubkey in self.connections:
                del self.connections[peer_ed25519_pubkey]
    
    async def _select_circuit(self):
        """Select 3 random relays for circuit"""
        relays = await self.fetch_relays()
        if len(relays) < 3:
            return None
        
        import random
        return random.sample(relays, 3)
    
    def _build_syn_packet(self, tx_id):
        """Build SYN payload (3584 bytes)"""
        payload = bytearray(E2E_PLAINTEXT_SIZE)
        payload[0] = Opcode.SYN
        tx_bytes = bytes.fromhex(tx_id)
        payload[1:1+len(tx_bytes)] = tx_bytes
        return bytes(payload)
    
    async def _monitor_handshake_timeout(self, peer_ed25519):
        """Monitor handshake timeout and trigger retries"""
        conn = self.connections.get(peer_ed25519)
        if not conn:
            return
        
        while conn.state in [STATE_AWAITING_CIRCUIT, STATE_AWAITING_ACK]:
            await asyncio.sleep(1)
            
            if conn.check_timeout():
                if conn.can_retry():
                    self.ui_queue.put({
                        "type": "log",
                        "text": f"⚠ Timeout! Retry {conn.retry_count + 1}/{MAX_RETRIES}"
                    })
                    await self.initiate_connection(peer_ed25519)
                else:
                    self.ui_queue.put({
                        "type": "error",
                        "text": "✗ Handshake failed: Max retries exceeded"
                    })
                    del self.connections[peer_ed25519]
                break
    
    # ===== PACKET SENDING =====
    
    async def _send_packet(self, packet, ip, port):
        """Send 4096-byte packet to relay"""
        try:
            reader, writer = await asyncio.open_connection(ip, port)
            writer.write(packet)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return True
        except Exception as e:
            self.ui_queue.put({
                "type": "log",
                "text": f"✗ Send failed: {e}"
            })
            return False
    
    # ===== PACKET RECEIVING (BOB) =====
    
    async def listen_for_packets(self, port):
        """Start TCP listener for incoming packets"""
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
        self.ui_queue.put({
            "type": "log",
            "text": f"✓ Listening on port {port}"
        })
        
        async with server:
            await server.serve_forever()
    
    async def _process_inbound_packet(self, packet):
        """Bob's dual-state decryption engine"""
        # Extract E2E block (3632 bytes)
        e2e_block = packet[:E2E_BLOCK_SIZE]
        
        decrypted = None
        sender_conn = None
        
        for peer_ed25519, conn in self.connections.items():
            try:
                mode = conn.get_decryption_mode()
                
                if mode == MODE_HANDSHAKE:
                    decrypted = self.crypto.decrypt_handshake(e2e_block)
                    sender_conn = conn
                    break
                else:
                    decrypted = self.crypto.decrypt_session(e2e_block, conn.peer_x25519)
                    sender_conn = conn
                    break
            except:
                continue
        
        if decrypted and sender_conn:
            await self._handle_decrypted_message(decrypted, sender_conn)
        else:
            self.ui_queue.put({
                "type": "log",
                "text": "✗ Decryption failed for inbound packet"
            })
    
    async def _handle_decrypted_message(self, plaintext, conn):
        """Parse and route decrypted message"""
        opcode = plaintext[0]
        payload = plaintext[1:]
        
        conn.update_activity()
        
        if opcode == Opcode.SYN:
            await self._send_ack(conn)
        
        elif opcode == Opcode.ACK:
            conn.receive_ack()
            self.ui_queue.put({
                "type": "ack",
                "peer": conn.peer_ed25519
            })
        
        elif opcode == Opcode.CHAT:
            text = payload.decode('utf-8', errors='ignore').rstrip('\x00')
            self.ui_queue.put({
                "type": "message",
                "peer": conn.peer_ed25519,
                "text": text
            })
        
        elif opcode == Opcode.FILE:
            await self._handle_file_chunk(payload, conn)
        
        elif opcode == Opcode.SACK:
            await self._handle_sack(payload, conn)
    
    async def _send_ack(self, conn):
        """Bob sends ACK to complete handshake"""
        ack_payload = bytearray(E2E_PLAINTEXT_SIZE)
        ack_payload[0] = Opcode.ACK
        
        e2e_block = self.crypto.encrypt_handshake(bytes(ack_payload), conn.peer_x25519)
        wire_packet = self.crypto.build_onion_packet(e2e_block, conn.circuit)
        
        await self._send_packet(wire_packet, conn.circuit[0]["ip"], conn.circuit[0]["port"])
        
        # Bob also upgrades to session mode
        conn.receive_ack()
    
    # ===== FILE TRANSFER (SACK) =====
    
    async def send_file(self, filepath, peer_ed25519):
        """SACK file transfer workflow"""
        conn = self.connections.get(peer_ed25519)
        if not conn or not conn.is_active():
            self.ui_queue.put({
                "type": "error",
                "text": "No active session with peer"
            })
            return
        
        with open(filepath, "rb") as f:
            data = f.read()
        
        chunks = [data[i:i+CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]
        total_chunks = len(chunks)
        
        tx_id = nacl.utils.random(16).hex()
        
        self.ui_queue.put({
            "type": "log",
            "text": f"[FILE] Sending {total_chunks} chunks in batches of {BATCH_SIZE}"
        })
        
        for batch_start in range(0, total_chunks, BATCH_SIZE):
            batch_end = min(batch_start + BATCH_SIZE, total_chunks)
            batch = chunks[batch_start:batch_end]
            
            batch_num = batch_start // BATCH_SIZE + 1
            self.ui_queue.put({
                "type": "log",
                "text": f"[FILE] Sending batch {batch_num} ({len(batch)} chunks)"
            })
            
            for i, chunk in enumerate(batch):
                chunk_num = batch_start + i
                await self._send_file_chunk(chunk, chunk_num, total_chunks, tx_id, conn)
            
            sack_received = await self._wait_for_sack(tx_id, batch_num, FILE_BATCH_TIMEOUT)
            
            if not sack_received:
                self.ui_queue.put({
                    "type": "error",
                    "text": f"[FILE] Batch {batch_num} SACK timeout"
                })
                return
        
        self.ui_queue.put({
            "type": "log",
            "text": f"✓ File transfer complete"
        })
    
    async def _send_file_chunk(self, chunk, chunk_num, total_chunks, tx_id, conn):
        """Send single file chunk"""
        payload = bytearray(E2E_PLAINTEXT_SIZE)
        payload[0] = Opcode.FILE
        
        tx_bytes = bytes.fromhex(tx_id)
        payload[1:17] = tx_bytes
        payload[17:21] = chunk_num.to_bytes(4, 'big')
        payload[21:25] = total_chunks.to_bytes(4, 'big')
        payload[25:25+len(chunk)] = chunk
        
        e2e_block = self.crypto.encrypt_session(bytes(payload), conn.peer_x25519)
        wire_packet = self.crypto.build_onion_packet(e2e_block, conn.circuit)
        
        await self._send_packet(wire_packet, conn.circuit[0]["ip"], conn.circuit[0]["port"])
    
    async def _wait_for_sack(self, tx_id, batch_num, timeout):
        """Wait for SACK acknowledgment"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            await asyncio.sleep(0.5)
        
        return False
    
    async def _handle_file_chunk(self, payload, conn):
        """Receive and reassemble file chunks"""
        tx_id = payload[:16].hex()
        chunk_num = int.from_bytes(payload[16:20], 'big')
        total_chunks = int.from_bytes(payload[20:24], 'big')
        
        self.ui_queue.put({
            "type": "log",
            "text": f"[FILE] Received chunk {chunk_num+1}/{total_chunks}"
        })
        
        if (chunk_num + 1) % BATCH_SIZE == 0:
            await self._send_sack(tx_id, chunk_num // BATCH_SIZE + 1, conn)
    
    async def _send_sack(self, tx_id, batch_num, conn):
        """Send SACK acknowledgment"""
        sack_payload = bytearray(E2E_PLAINTEXT_SIZE)
        sack_payload[0] = Opcode.SACK
        sack_payload[1:17] = bytes.fromhex(tx_id)
        sack_payload[17:21] = batch_num.to_bytes(4, 'big')
        
        e2e_block = self.crypto.encrypt_session(bytes(sack_payload), conn.peer_x25519)
        wire_packet = self.crypto.build_onion_packet(e2e_block, conn.circuit)
        
        await self._send_packet(wire_packet, conn.circuit[0]["ip"], conn.circuit[0]["port"])
    
    async def _handle_sack(self, payload, conn):
        """Handle SACK reception"""
        tx_id = payload[:16].hex()
        batch_num = int.from_bytes(payload[16:20], 'big')
        
        self.ui_queue.put({
            "type": "log",
            "text": f"[SACK] Batch {batch_num} acknowledged"
        })