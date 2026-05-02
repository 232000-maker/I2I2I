# plan_crypto.md

## Domain: Core Cryptography

**Target Files:** `src/onion_crypto.py`

### 1. Integration Contract

- **Role:** Pure mathematical and cryptographic black box.
- **Inputs:** Accepts a plaintext payload (string or bytes) and an ordered routing path (list of node cryptographic and network identifiers).
- **Outputs:** Strictly yields a fully padded, encrypted 4096-byte `bytearray`.
- **Agnosticism:** This domain contains zero awareness of sockets, queues, threading, or event loops. It performs CPU-bound synchronous cryptographic transformations and byte packing only.

### 2. Key Hierarchy

Every node generates exactly one persistent key pair. Key derivation occurs strictly at startup. On-the-fly derivation is forbidden.

- **Ed25519 Signing Key:** `nacl.signing.SigningKey`. Used for persistent identity, registration signatures, and directory authentication.
- **Ed25519 Verify Key:** `nacl.signing.VerifyKey`. Used for peer identity verification.
- **X25519 Private Key:** Derived via `.to_curve25519_private_key()`. Used for SealedBox decryption. Kept in memory cache.
- **X25519 Public Key:** Derived via `.to_curve25519_public_key()`. Used for SealedBox encryption. Registered to the directory.

Persistence directory structure:

```text
keys/
  identity.key
  identity.pub
  x25519.pub
```

### 3. Opcode Namespace

The first byte of the structural header strictly dictates the instruction.

| Hex  | Definition | Purpose                            |
| ---- | ---------- | ---------------------------------- |
| 0x00 | REG        | Directory Registration             |
| 0x01 | SYN        | Handshake Initiation               |
| 0x02 | CHAT       | Standard Text Message              |
| 0x03 | FILE       | File Transfer Chunk                |
| 0x04 | ACK        | General Acknowledgment             |
| 0x05 | PING       | Network Keepalive/Test             |
| 0x06 | PONG       | Network Keepalive Response         |
| 0x07 | SACK       | File Transfer Batch Acknowledgment |
| 0xFF | ERR        | Protocol Exception/Error           |

### 4. The 4096-Byte Mathematical Framing

Every wire frame generated or parsed by this domain must equal exactly 4096 bytes. Variable-length outputs are strictly prohibited.

#### 4.1 Wire Frame Layout

- **Nonce:** 24 bytes
- **Header:** 64 bytes
- **Payload:** 3632 bytes
- **Padding:** 376 bytes
- **Total:** 4096 bytes

#### 4.2 Header Struct Definition

The 64-byte routing header utilizes the exact `struct` format `!B 32s 4s H 25s`.

- `!B` (1 byte): Instruction (Opcode)
- `32s` (32 bytes): Dest_PubKey (X25519 Public Key)
- `4s` (4 bytes): Next_IP (IPv4 address, packed)
- `H` (2 bytes): Next_Port (Unsigned short integer)
- `25s` (25 bytes): Random Noise Padding
- **Total:** 64 bytes

#### 4.3 Envelope Step Offsets

The 3-hop onion wrapping process relies on strict 112-byte mathematical offsets to account for the 48-byte PyNaCl `SealedBox` overhead at each layer. Legacy 80-byte offset logic is deprecated.

The offsets define the starting point of the inner layer within the outer layer's payload space:

- **Hop 3 Offset:** 24
- **Hop 2 Offset:** 136
- **Hop 1 Offset:** 248
- **Step Size:** 112 bytes

**Layer Construction Math:**

- Hop 3 plaintext = 3648B → Hop 3 SealedBox = 3696B
- Hop 2 plaintext = 3760B → Hop 2 SealedBox = 3808B
- Hop 1 plaintext = 3872B → Hop 1 SealedBox = 3920B
- Wire packet = 4096B

#### 4.4 Indistinguishability Invariant

The End-to-End (E2E) last-mile delivery block must maintain mathematical indistinguishability between Handshake frames and Session frames. The total E2E block is exactly 3632 bytes.

- **Handshake Phase (SealedBox):** Requires no prior shared secret. Overhead is 48 bytes.
  - Calculation: `3584B plaintext + 48B overhead = 3632B`
- **Session Phase (SecretBox):** Requires shared secret. Overhead is 40 bytes. Requires 8 bytes of random noise to equalize the frame.
  - Calculation: `3584B plaintext + 8B noise + 40B overhead = 3632B`

The final 4096-byte packet delivered to the destination client consists of the 3632-byte E2E block followed by 464 bytes of random noise.

### 5. Phased Execution Plan (Cryptography Scope)

The Master Specification defines a 7-phase execution plan from crypto to the full system. This domain constitutes the foundational phases.

- **Goal:** Build and verify all raw cryptographic primitives, offset step sizes, and indistinguishability mathematical logic.
- **Steps:**
  1. Lock in the exactly 64-byte Header Struct layout.
  2. Build Key Hierarchy generation and storage logic.
  3. Construct Handshake and Session encryption modes.
  4. Implement the 112-byte offset onion builder.
- **Gate:** Unit tests must programmatically assert that every output frame strictly equals 4096 bytes and successfully trial-peels locally before moving to network integration phases.
