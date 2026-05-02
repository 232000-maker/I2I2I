# I2I2I (Version 2.0)
**Anonymous Communication System | 3-Hop Onion Routing + Mix-Network**

Welcome to the v2.0 rebuild of I2I2I. We are moving from a legacy synchronous proof-of-concept to a fully asynchronous, byte-perfect, Dockerized mix-network. 

Because of the extreme cryptographic and threading constraints in this architecture, we are strictly dividing the workload into three isolated domains. 

---

## 🧠 The AI-Assisted Workflow (Domain-Driven Development)

We are using AI coding agents to accelerate this build, but **DO NOT feed the entire codebase to your AI at once.** If you ask an LLM to build the whole system, it will hallucinate, run out of memory, and create massive merge conflicts.

Instead, we are using **Domain-Driven Prompting**. 
In the `docs/` folder, you will find three Mini-Specs (`plan_crypto.md`, `plan_network.md`, `plan_client.md`). You will only feed your specific Mini-Spec and the legacy `code.md` to your AI agent. 

**Your workflow:**
1. Open a fresh chat with your AI agent.
2. Upload the legacy `code.md` (for context) and **ONLY your assigned `plan_*.md` file**.
3. Prompt the AI to build your specific components based *strictly* on your plan.
4. Test your domain in isolation (use mock data to simulate the other domains).
5. Push to your assigned branch.

---

## 🛠️ The Three Domains & Role Assignments

Find your assigned role below. You must respect your "Integration Contract"—this guarantees your code will snap together with the rest of the team's code during the grand merge.

### 1. The Crypto Core (Lead: Domain 1)
* **Your Spec:** `docs/plan_crypto.md`
* **Your Branch:** `feature/crypto-core`
* **Target Files:** `src/onion_crypto.py`
* **Your Mission:** You are building the mathematical heart of the system. You own the 4096-byte frame, the Opcode dictionary, and the PyNaCl `SealedBox`/`SecretBox` wrap and peel logic using the new 112-byte offsets.
* **Integration Contract:** Your module is a pure black box. The Network team will hand you raw 4096B bytearrays to decrypt. You will hand the Network team fully encrypted 4096B bytearrays to send. You do not touch sockets or queues.

### 2. Network & Infrastructure (Lead: Domain 2)
* **Your Spec:** `docs/plan_network.md`
* **Your Branch:** `feature/network-infra`
* **Target Files:** `relay_node.py`, `directory_api.py`, `docker-compose.yml`, `Dockerfile.headless`
* **Your Mission:** You are building the plumbing. You own the Flask Directory API (with Ed25519 signature verification) and the `asyncio` Relay TCP servers. You handle trial peeling and the 60s nonce sweep.
* **Integration Contract:** You handle wire transmission. Assume all 4096-byte packets passed to you from the Crypto team are perfectly formed. For testing, just pass arrays of random bytes through your async relays to ensure they don't drop packets.

### 3. UI & Client Integrator (Lead: Domain 3)
* **Your Spec:** `docs/plan_client.md`
* **Your Branch:** `feature/ui-client`
* **Target Files:** `gui/app.py`, `src/i2p_manager.py`, `src/peer_connection.py`, `Dockerfile.client`
* **Your Mission:** You own the user experience and the thread bridge. You must enforce the "Two-World Rule": Tkinter lives on the main thread, networking lives on the background thread, and they ONLY communicate via a thread-safe `queue.Queue`. You also own the File Transfer (SACK) state machine.
* **Integration Contract:** You handle state and user input. For testing, mock the cryptographic function calls (e.g., `dummy_encrypt()`). Focus entirely on ensuring the Tkinter GUI does not freeze when the background async loop is running.

---

## 🚀 Rules of Engagement

1. **Never commit directly to `main`.** Work only in your `feature/` branch.
2. **Respect the Contracts.** Do not write code that bleeds into someone else's domain. If the UI dev needs a specific data structure from the Crypto dev, communicate it in Discord, don't just hack it into your file.
3. **Mock First, Merge Later.** Prove your component works in a vacuum before we attempt the final integration.

### Quickstart
```bash
# Clone the repo
git clone <repo-url>
cd I2I2I

# Checkout your assigned branch
git checkout feature/<your-domain>

# Read your spec
cat docs/plan_<your-domain>.md
