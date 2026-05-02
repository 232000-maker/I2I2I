# plan_client.md

## Domain: UI & Thread Bridge

**Target Files:** `gui/app.py`, `src/i2p_manager.py`, `src/peer_connection.py`, `Dockerfile.client`

### 1. Integration Contract

- **Role:** User interface, state management, and thread coordination.
- **Inputs/Outputs:** Captures user input (text/files) to pass to the Cryptography domain. Receives inbound network byte arrays routed from the Network domain.
- **Agnosticism:** This domain does not directly process cryptographic mathematical framing or raw socket operations. It initially mocks cryptographic functions for UI testing. It relies entirely on the Network domain to deliver incoming data arrays via a thread-safe queue.

### 2. Threading & Concurrency Model (The Two-World Rule)

This is the absolute critical architectural constraint for the client domain. Violations will cause UI deadlocks or silent data corruption.

#### 2.1 UI World (Main Thread)

- **Permitted:** All Tkinter widgets, `root.mainloop()`, `root.after()` callbacks.
- **FORBIDDEN:** Any `asyncio` calls, any blocking I/O, any socket operations.

#### 2.2 Network World (Daemon `threading.Thread`)

- **Permitted:** `asyncio` event loop, all TCP connections, all cryptographic operations.
- **FORBIDDEN:** Any Tkinter widget reads or writes. `asyncio.get_event_loop()` must never be used here; the loop must be managed explicitly:
  ```python
  loop = asyncio.new_event_loop()
  asyncio.set_event_loop(loop)
  loop.run_forever()
  ```

#### 2.3 The Bridge

A single `queue.Queue` instance is the ONLY legal crossing point between the two worlds.

- **Network to UI:** The Network world pushes update events to the queue: `q.put({"type": "message", "peer": ..., "text": ...})`.
- **UI Polling:** The UI world continuously polls the queue using a scheduled callback: `root.after(100, process_queue)`.

### 3. Client Infrastructure

The graphical client uses `Dockerfile.client`.

- **Environment:** Full stack utilizing `python:3.10-slim-bookworm` + Xvfb + fluxbox + x11vnc + noVNC + python3-tk + all Python dependencies. Runs as non-root `i2iuser`.
- **Entrypoint:** Starts Xvfb, then launches `main.py`.
- **Networking:** Host port 8777 mapped to 8080 (Client A), and host port 8778 mapped to 8080 (Client B) for browser-based noVNC access.

### 4. Client State Machines & Workflows

#### 4.1 Bob's Dual Decryption State Machine

The receiving client (Bob) operates a dual-state decryption engine for inbound last-mile packets. Trial peeling is strictly forbidden for the client. The state dictates the expected decryption primitive.

- **HANDSHAKE Mode:** Bob expects a 3632-byte `SealedBox`. No prior shared secret exists.
- **SESSION Mode:** Following a successful Handshake_ACK, Bob transitions to this mode. Bob expects a 3632-byte `SecretBox` (3584B payload + 8B random noise + 40B overhead).

#### 4.2 Handshake Initiation Flow (Alice)

When Alice initiates contact, the client follows a rigid 7-step sequence:

1.  Generate transaction ID.
2.  Select relay circuit.
3.  Query directory for Bob's LeaseSet.
4.  Build SYN packet.
5.  Encrypt via Cryptography domain.
6.  Send to Hop 1.
7.  Wait for ACK.

**Session Upgrade States:** `AWAITING_CIRCUIT` -> `AWAITING_ACK` -> `SESSION_ACTIVE`.

- **Timeout Constraints:** The client enforces a strict 30-second general timeout for the handshake sequence and network wait times.
- **Retries:** The client permits a maximum of 3 retries for the handshake sequence if the 30-second timeout expires.

#### 4.3 File Transfer (SACK) Workflow

Large file transfers bypass the standard message flow and utilize batching to ensure reliability over the anonymous mix-network.

- **Chunk Size:** Exactly 3563 bytes per chunk.
- **Batch Size:** 50 chunks per batch before requiring acknowledgment.
- **Timeout:** 120 seconds for the entire batch operation.
- **Flush:** System enforces an 8-second flush interval for partial batches.

### 5. Phased Execution Plan (Client Scope)

The Master Specification defines a 7-phase execution plan. This domain manages the final UI and End-to-End integration phases.

- **Goal:** Establish the Two-World thread bridge, user interaction flow, and high-level dual-state session tracking.
- **Steps:**
  1. Build the Tkinter GUI and `queue.Queue` bridge polling mechanism.
  2. Implement the Handshake and Bob's Dual State logic mapped to the 30s timeout and 3-retry bounds.
  3. Implement SACK file transfer chunking and batch management.
  4. Connect the Network domain's event loop to the Cryptography domain's black box within the daemon thread.
- **Gate:** Complete End-to-End communication between `client-a` and `client-b` over the `i2i-mesh` relay network, successfully passing text and files while adhering to all threading and timeout constraints without UI deadlocks.
