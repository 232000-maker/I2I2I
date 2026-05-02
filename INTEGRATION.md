# I2I2I — Crypto Module Integration Guide

**Module:** `src/onion_crypto.py`  
**Author:** Huzzi (Crypto Domain)  
**Spec:** Masterplan v2.0 Final  
**Status:** All 53 unit tests passing ✅

---

## For the Relay Node Developer (`relay_node.py`)

### 1. Startup — Key Initialisation

Call `KeyHierarchy.initialise()` **once at node startup**, before the asyncio event loop begins. This generates or loads keys from disk and caches the X25519 derivation. Never call it inside the loop.

```python
from src.onion_crypto import KeyHierarchy

key_hier = KeyHierarchy()   # uses default keys/ directory
key_hier.initialise()       # derive once, cache forever
```

---

### 2. Receiving a Packet — Trial Peel

Every incoming TCP read must be exactly **4096 bytes**. Pass it directly to `trial_peel`.

```python
from src.onion_crypto import trial_peel
import nacl.exceptions

raw_frame = await reader.readexactly(4096)   # Network World only

try:
    header, inner_bytes = trial_peel(raw_frame, key_hier)
except nacl.exceptions.CryptoError:
    # Packet not for this node, or tampered — drop silently
    return
```

`header` is a dict with these keys:

| Key | Type | Description |
|---|---|---|
| `opcode` | `int` | Instruction byte (e.g. `0x02` = CHAT) |
| `dest_pubkey` | `bytes` (32B) | Next hop's X25519 public key |
| `next_ip` | `str` | Next hop's IPv4 address |
| `next_port` | `int` | Next hop's TCP port |

`inner_bytes` is the decrypted payload — the raw bytes to re-wrap and forward.

---

### 3. Forwarding — Re-pad and Send

After peeling, re-assemble a fresh 4096B frame and forward it. Use a fresh nonce and a fresh header pointing to the next hop.

```python
from src.onion_crypto import pack_header, assemble_frame
import nacl.utils

# Build the forwarding header using the decrypted routing info
fwd_header = pack_header(
    opcode       = header["opcode"],
    dest_pubkey  = header["dest_pubkey"],
    next_ip      = header["next_ip"],
    next_port    = header["next_port"],
)

# Re-pad inner_bytes to exactly 3632B (trim or pad as needed)
payload = inner_bytes[:3632].ljust(3632, b"\x00")

new_nonce = nacl.utils.random(24)
outgoing_frame = assemble_frame(new_nonce, fwd_header, payload)

writer.write(bytes(outgoing_frame))
await writer.drain()
```

---

### 4. Last-Hop Gateway — Deliver to Bob

The gateway relay (Hop 3) does **not** forward to another relay. Instead, it builds the last-mile block and delivers it directly to Bob's registered listener socket.

```python
from src.onion_crypto import build_last_mile_block

# inner_bytes from trial_peel is the E2E block (3632B)
last_mile = build_last_mile_block(inner_bytes[:3632])

# Send the 4096B last-mile block to Bob
bob_writer.write(bytes(last_mile))
await bob_writer.drain()
```

> **Critical:** Bob does **not** perform trial peeling. The last-mile block is `[3632B E2E block][464B random noise]`. Bob reads the first 3632 bytes and decrypts the E2E block directly.

---

### 5. Mix Delay

After peeling and before forwarding, apply the mix delay defined in the Masterplan (0.5–2.0 seconds random). This is your domain's responsibility, not the crypto module's.

```python
import random, asyncio
await asyncio.sleep(random.uniform(0.5, 2.0))
```

---

## For the Client / GUI Developer (`main.py`)

### 1. Startup — Key Initialisation

Same as relay — call once in the **Network World thread**, before any connections are made.

```python
from src.onion_crypto import KeyHierarchy

key_hier = KeyHierarchy()
key_hier.initialise()
```

---

### 2. Building NodeDescriptors from Directory Responses

Query the directory API to get relay info, then wrap each relay in a `NodeDescriptor`.

```python
from src.onion_crypto import NodeDescriptor

# resp is a JSON object from the directory API for one relay
desc = NodeDescriptor(
    ed25519_pubkey = bytes.fromhex(resp["ed25519_pubkey"]),
    x25519_pubkey  = bytes.fromhex(resp["x25519_pubkey"]),
    ip             = resp["ip"],
    port           = int(resp["port"]),
)
```

Build a list of exactly 3 descriptors: `[hop1, hop2, hop3_gateway]`.

---

### 3. Sending a Message (Alice → Onion)

Use `build_chat_packet` to produce a ready-to-send 4096B bytearray. Call this inside the **Network World thread only**.

```python
from src.onion_crypto import build_chat_packet

routing_path = [hop1_desc, hop2_desc, hop3_desc]   # 3 NodeDescriptors

frame = build_chat_packet(message_text, routing_path)   # bytearray, 4096B

writer.write(bytes(frame))
await writer.drain()
```

Other convenience builders:

```python
from src.onion_crypto import build_ping_packet, build_onion_packet, Opcode

ping_frame = build_ping_packet(routing_path)
file_frame = build_onion_packet(chunk_bytes, routing_path, opcode=Opcode.FILE)
```

---

### 4. Receiving a Message (Bob — Handshake Phase)

Bob receives a 4096B last-mile block. Extract and decrypt the E2E block using `SealedBox` (no shared secret needed yet).

```python
from src.onion_crypto import extract_e2e_block, decrypt_e2e_handshake

raw = await reader.readexactly(4096)          # Network World only

e2e_block  = extract_e2e_block(raw)           # first 3632B
plaintext  = decrypt_e2e_handshake(e2e_block, key_hier.x25519_private)
# plaintext is 3584B — strip null padding to recover original message
message = plaintext.rstrip(b"\x00").decode("utf-8")
```

---

### 5. Receiving a Message (Bob — Session Phase)

Once a `shared_secret` has been established via the SYN/ACK handshake, switch to SecretBox decryption.

```python
from src.onion_crypto import extract_e2e_block, decrypt_e2e_session

raw = await reader.readexactly(4096)

e2e_block = extract_e2e_block(raw)
plaintext = decrypt_e2e_session(e2e_block, shared_secret)
message   = plaintext.rstrip(b"\x00").decode("utf-8")
```

The two paths produce identically-sized E2E blocks (3632B), so Bob cannot distinguish a handshake packet from a session packet by length alone.

---

### 6. Threading Rule (Critical)

All crypto calls are **synchronous and CPU-bound**. They must only run in the **Network World thread** (the asyncio daemon thread). Never call any function from `onion_crypto` in the Tkinter main thread.

```
# LEGAL — inside asyncio coroutine or Network World thread
frame = build_chat_packet(text, path)

# ILLEGAL — inside any Tkinter callback, root.after(), or button command
frame = build_chat_packet(text, path)  # ← will block the UI
```

Use the `queue.Queue` bridge to pass data between worlds:

```python
# Network World: push decrypted message to queue
q.put({"type": "message", "peer": peer_addr, "text": message})

# UI World: root.after(100, process_queue) reads from queue and updates widgets
```

---

## Shared Constants Reference

These are exported from `onion_crypto` and can be imported by any domain:

```python
from src.onion_crypto import (
    FRAME_SIZE,          # 4096  — every wire packet
    NONCE_SIZE,          # 24    — anti-replay nonce
    HEADER_SIZE,         # 64    — routing header
    PAYLOAD_SIZE,        # 3632  — E2E block field
    PADDING_SIZE,        # 376   — tail noise on wire frame
    E2E_BLOCK_SIZE,      # 3632  — handshake and session both
    E2E_PLAINTEXT_SIZE,  # 3584  — max usable application payload
    LAST_MILE_NOISE,     # 464   — noise on Bob's delivery block
    Opcode,              # REG, SYN, CHAT, FILE, ACK, PING, PONG, SACK, ERR
    NodeDescriptor,      # dataclass: ed25519_pubkey, x25519_pubkey, ip, port
    KeyHierarchy,        # key manager class
)
```

---

## Import Cheat Sheet

| Need | Import |
|---|---|
| Build a chat packet | `from src.onion_crypto import build_chat_packet` |
| Build any opcode packet | `from src.onion_crypto import build_onion_packet, Opcode` |
| Peel a relay layer | `from src.onion_crypto import trial_peel` |
| Decrypt Bob's message (handshake) | `from src.onion_crypto import extract_e2e_block, decrypt_e2e_handshake` |
| Decrypt Bob's message (session) | `from src.onion_crypto import extract_e2e_block, decrypt_e2e_session` |
| Re-assemble a forwarding frame | `from src.onion_crypto import pack_header, assemble_frame` |
| Key management | `from src.onion_crypto import KeyHierarchy` |
| Node info wrapper | `from src.onion_crypto import NodeDescriptor` |
