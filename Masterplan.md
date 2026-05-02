# I2I2I

## MASTER SPECIFICATION DOCUMENT

### Version 2.0 — Final (Locked)

Anonymous Communication System
3-Hop Onion Routing + Mix-Network Architecture

---

**Document Status:**
All architectural reviews, gap analyses, and edge-case resolutions are complete and incorporated. This is the single source of truth. A developer must be able to build the entire system using only this file.

---

# 1. System Topology & Infrastructure

## 1.1 Network Architecture

I2I2I is a location-hiding, traffic-analysis-resistant messaging and file-sharing system. It is not a direct peer-to-peer system. No client ever connects directly to another client.

The network consists of four distinct node roles:

**Role | Count | Binary | Description**
Directory Server | 1 minimum | directory_api.py | Central Flask registry. Stateless between restarts.
Relay Node | 4 minimum | relay_node.py | Headless asyncio TCP server. Routes and delays packets.
Gateway Relay | 1 (of the 4) | relay_node.py | A standard relay that also holds Bob's registered listener socket. Last-hop role, not a separate binary.
Client | 2+ | main.py + GUI | Tkinter GUI with background asyncio thread.

---

### Traffic Flow: Alice → Bob

```
Alice (Client)
  │
  ▼  [Direct TCP, onion-wrapped 4096B packet]
Relay 1 (Hop 1) ─── peels outer layer, re-pads, forwards
  │
  ▼  [4096B packet, re-padded]
Relay 2 (Hop 2) ─── peels middle layer, re-pads, forwards
  │
  ▼  [4096B packet, re-padded]
Relay 3 / Gateway (Hop 3) ─── peels inner layer, delivers
  │
  ▼  [Raw last-mile: 3632B E2E Block + 464B noise = 4096B]
Bob (Client)
```

**CRITICAL:**
Every packet on every wire segment is exactly 4096 bytes. There are no variable-length packets anywhere in the routing layer.

---

## 1.2 Docker Infrastructure

docker-compose.yml defines 7 services on a single isolated bridge network named i2i-mesh.

|**Service Name | Image Type | Host Ports | Notes** |
|directory | Dockerfile.headless | 5001:5001 | Flask API only, no GUI|
|relay-1 | Dockerfile.headless | none exposed | Internal routing only|
|relay-2 | Dockerfile.headless | none exposed | Internal routing only|
|relay-3 | Dockerfile.headless | none exposed | Internal routing only|
|relay-4 | Dockerfile.headless | none exposed | Internal routing only|
|client-a | Dockerfile.client | 8777:8080 (noVNC) | Full GUI + Xvfb stack|
|client-b | Dockerfile.client | 8778:8080 (noVNC) | Full GUI + Xvfb stack|

---

### Two Dockerfile Variants

- Dockerfile.client: Full stack — python:3.10-slim-bookworm + Xvfb + fluxbox + x11vnc + noVNC + python3-tk + all Python deps. Non-root i2iuser. Entrypoint starts Xvfb then launches main.py.
- Dockerfile.headless: Minimal — python:3.10-slim-bookworm + Python deps only. No X11 stack. Runs relay_node.py or directory_api.py directly.

**NOTE:**
Docker DNS: Services reference each other by service name (e.g., relay-1, directory). The circuit selector must detect the Docker environment via I2I_IN_DOCKER=true and resolve names accordingly.

---

## 1.3 Threading & Concurrency Model

**CRITICAL:**
This is the most critical architectural constraint in the entire system. Violating it causes deadlocks or silent data corruption.

### The Two-World Rule

**World | Thread | What Lives Here | What Is FORBIDDEN Here**
UI World | Main thread | All Tkinter widgets, root.mainloop(), root.after() callbacks | Any asyncio call, any blocking I/O, any socket operation
Network World | Daemon threading.Thread | asyncio event loop, all TCP connections, all cryptographic operations | Any tkinter widget read or write

Communication bridge: A single queue.Queue instance (thread-safe) is the ONLY legal crossing point between the two worlds.

- Network world pushes update events:
  `q.put({"type": "message", "peer": ..., "text": ...})`

- UI world polls via:
  `root.after(100, process_queue)`

---

### asyncio Event Loop Lifecycle

```
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
loop.run_forever()
```

NEVER use asyncio.get_event_loop() in a non-main thread.

---

# 2. Cryptographic Key Hierarchy

## 2.1 Key Types and Their Roles

**Key Type | PyNaCl Class | Purpose | Scope**

Ed25519 Signing Key | nacl.signing.SigningKey | Identity, registration signatures, directory authentication | Persistent
Ed25519 Verify Key | nacl.signing.VerifyKey | Peer identity verification | Derived
X25519 Private Key | Derived via .to_curve25519_private_key() | SealedBox decryption | Cached
X25519 Public Key | Derived via .to_curve25519_public_key() | SealedBox encryption | Registered

---

## 2.2 Key Derivation Rules

### Rule 1 — Single root, two branches

Every node generates exactly one nacl.signing.SigningKey.

### Rule 2 — Derive once, cache forever

X25519 keys derived once at startup.

### Rule 3 — No on-the-fly derivation

Always use stored directory keys.

### Rule 4 — Key persistence

```
keys/
  identity.key
  identity.pub
  x25519.pub
```

---

## 2.3 Encryption Primitives

### SealedBox (Handshake Phase)

- Overhead: 48 bytes
- No prior shared secret required

### SecretBox (Session Phase)

- Overhead: 40 bytes
- +8 bytes random noise
- Total overhead = 48 bytes

---

### Indistinguishability Invariant

```
Handshake (SealedBox): 3584B + 48B = 3632B
Session   (SecretBox): 3584B + 8B + 40B = 3632B
```

---

## 2.4 LeaseSet and Relay Registration

Relay fields:
ed25519_pubkey, x25519_pubkey, ip, port

LeaseSet fields:
ed25519_pubkey, x25519_pubkey, gateway_ip, gateway_port

---

# 3. The 4096-Byte Mathematical Framing

## 3.1 Wire Frame Layout

Nonce — 24 bytes
Header — 64 bytes
Payload — 3632 bytes
Padding — 376 bytes

Total: 4096 bytes

---

## 3.2 Header Format

Instruction
Dest_PubKey
Next_IP
Next_Port
Random Padding

Total: 64 bytes

---

## 3.3 Offset Calculation

**CRITICAL:** Correct offsets are locked.

Offsets:
24
136
248

Offset step size: 112 bytes

---

### Layer Construction

```
Hop 3 plaintext  = 3648B
Hop 3 SealedBox  = 3696B
Hop 2 plaintext  = 3760B
Hop 2 SealedBox  = 3808B
Hop 1 plaintext  = 3872B
Hop 1 SealedBox  = 3920B
Wire packet      = 4096B
```

---

## 3.4 Last-Mile Delivery

```
[3632B E2E Block][464B Random Noise]
```

**CRITICAL:**
Bob does NOT perform trial peeling.

---

# 4. Opcode Namespace

0x00 REG
0x01 SYN
0x02 CHAT
0x03 FILE
0x04 ACK
0x05 PING
0x06 PONG
0x07 SACK
0xFF ERR

---

# 5. Directory API Contracts

Stateless Flask server. Nodes must re-register every 30 seconds.

Base URL:
[http://directory:5001](http://directory:5001)

---

## Security

Timestamp jitter
Rate limiting
Signature verification

---

# 6. Operational Workflows & State Machines

## Relay Node Flow

```
while True:
    packet = read 4096 bytes
    validate nonce
    trial peel
    delay
    forward or deliver
```

---

## Handshake Flow

1. Generate transaction ID
2. Select circuit
3. Query LeaseSet
4. Build SYN
5. Encrypt
6. Send
7. Wait for ACK

Retries: 3

---

## Session Upgrade

States:
AWAITING_CIRCUIT
AWAITING_ACK
SESSION_ACTIVE

---

## Bob Decryption

Modes:
HANDSHAKE → SESSION

---

## File Transfer (SACK)

Chunk size: 3563 bytes
Batch size: 50
Timeout: 120s

---

# 7. Phased Execution Plan

7 phases from crypto → full system

Each phase includes:
Goal
Steps
Gate

---

# Appendix A: Constants

4096B packet
24B nonce
64B header
3632B payload
Offsets: 24, 136, 248
Chunk: 3563B
Delay: 0.5–2.0s
Timeout: 30s
Retries: 3

---

# Appendix B: Opcode Table

REG, SYN, CHAT, FILE, ACK, PING, PONG, SACK, ERR

---

# Appendix C: v1 Codebase

Partial reuse, major rewrites

---

**End of I2I2I Master Specification Document v2.0 — Final**

---
