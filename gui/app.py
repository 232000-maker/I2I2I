import os
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import queue
import asyncio
from src.i2p_manager import I2PManager
from src.crypto_wrapper import CryptoWrapper
from src.constants import *

CLIENT_PORT = int(os.getenv("CLIENT_PORT", "7000"))
CLIENT_GATEWAY_IP = os.getenv("CLIENT_GATEWAY_IP", "127.0.0.1")


class I2I2IClient:
    def __init__(self, root):
        self.root = root
        self.root.title("I2I Anonymous Client")
        self.root.geometry("900x700")
        self.root.configure(bg="#191724")

        self.ui_queue = queue.Queue()
        self.crypto = CryptoWrapper()
        self.network = I2PManager(self.crypto, self.ui_queue)
        self.network_loop = None
        self._loop_ready = threading.Event()
        self.current_peer = None

        self._build_ui()
        self._start_network_thread()
        self._poll_queue()

    def _build_ui(self):
        banner = tk.Frame(self.root, bg="#1f1d2e", height=100)
        banner.pack(fill=tk.X)
        banner.pack_propagate(False)

        tk.Label(
            banner, text="I2I", font=("Arial", 24, "bold"), fg="#9ccfd8", bg="#1f1d2e"
        ).pack(pady=5)

        tk.Label(
            banner,
            text="Anonymous Communication System | 3-Hop Onion Routing",
            font=("Arial", 10),
            fg="#e0def4",
            bg="#1f1d2e",
        ).pack()

        self.status_label = tk.Label(
            banner,
            text="Status: Initializing...",
            font=("Arial", 10, "bold"),
            fg="#31748f",
            bg="#1f1d2e",
        )
        self.status_label.pack(pady=5)

        # Identity panel with copy button
        id_frame = tk.Frame(self.root, bg="#26233a", height=60)
        id_frame.pack(fill=tk.X, padx=10, pady=5)
        id_frame.pack_propagate(False)

        tk.Label(
            id_frame,
            text="My Ed25519:",
            font=("Courier", 9),
            fg="#e0def4",
            bg="#26233a",
        ).pack(side=tk.LEFT, padx=10)

        self._full_pubkey = self.crypto.get_ed25519_pubkey()

        self.my_pubkey_label = tk.Label(
            id_frame,
            text=self._full_pubkey[:32] + "...",
            font=("Courier", 9),
            fg="#9ccfd8",
            bg="#26233a",
        )
        self.my_pubkey_label.pack(side=tk.LEFT)

        tk.Button(
            id_frame,
            text="Copy Key",
            command=self._copy_pubkey,
            bg="#1f1d2e",
            fg="#9ccfd8",
            font=("Arial", 8, "bold"),
            relief=tk.FLAT,
            cursor="hand2",
            padx=6,
        ).pack(side=tk.LEFT, padx=8)

        # Peer connection panel
        peer_frame = tk.Frame(self.root, bg="#191724")
        peer_frame.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(
            peer_frame,
            text="Connect to Peer:",
            font=("Arial", 11, "bold"),
            fg="#e0def4",
            bg="#191724",
        ).pack(anchor=tk.W)

        entry_row = tk.Frame(peer_frame, bg="#191724")
        entry_row.pack(fill=tk.X, pady=5)

        tk.Label(
            entry_row,
            text="Ed25519 PubKey:",
            font=("Arial", 9),
            fg="#6e6a86",
            bg="#191724",
        ).pack(side=tk.LEFT)

        self.peer_entry = tk.Entry(
            entry_row,
            width=70,
            font=("Courier", 9),
            bg="#1f1d2e",
            fg="#e0def4",
            insertbackground="#e0def4",
        )
        self.peer_entry.pack(side=tk.LEFT, padx=10)

        tk.Button(
            entry_row,
            text="Connect",
            command=self.initiate_handshake,
            bg="#31748f",
            fg="#e0def4",
            font=("Arial", 10, "bold"),
            relief=tk.FLAT,
            cursor="hand2",
        ).pack(side=tk.LEFT)

        # Chat area
        chat_frame = tk.Frame(self.root, bg="#191724")
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        tk.Label(
            chat_frame,
            text="Conversation:",
            font=("Arial", 11, "bold"),
            fg="#e0def4",
            bg="#191724",
        ).pack(anchor=tk.W)

        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            height=20,
            font=("Courier", 9),
            bg="#26233a",
            fg="#e0def4",
            state=tk.DISABLED,
            insertbackground="#e0def4",
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=5)

        self.chat_display.tag_config("system", foreground="#9ccfd8")
        self.chat_display.tag_config("sent", foreground="#31748f")
        self.chat_display.tag_config("received", foreground="#f6c177")
        self.chat_display.tag_config("error", foreground="#eb6f92")
        self.chat_display.tag_config("handshake", foreground="#9ccfd8")

        # Input area
        input_frame = tk.Frame(self.root, bg="#191724")
        input_frame.pack(fill=tk.X, padx=10, pady=10)

        self.message_entry = tk.Entry(
            input_frame,
            font=("Arial", 11),
            bg="#1f1d2e",
            fg="#e0def4",
            insertbackground="#e0def4",
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.message_entry.bind("<Return>", lambda e: self.send_message())

        tk.Button(
            input_frame,
            text="Send",
            command=self.send_message,
            bg="#f6c177",
            fg="#191724",
            font=("Arial", 10, "bold"),
            width=10,
            relief=tk.FLAT,
            cursor="hand2",
        ).pack(side=tk.LEFT, padx=2)

        tk.Button(
            input_frame,
            text="Send File",
            command=self.send_file,
            bg="#c4a7e7",
            fg="#191724",
            font=("Arial", 10, "bold"),
            width=10,
            relief=tk.FLAT,
            cursor="hand2",
        ).pack(side=tk.LEFT, padx=2)

    def _copy_pubkey(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self._full_pubkey)
        self.root.update()
        self.append_chat("[SYSTEM] Ed25519 public key copied to clipboard", "system")

    def _start_network_thread(self):
        def network_worker():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.network_loop = loop
            self._loop_ready.set()

            async def startup():
                await self.network.register_with_directory(
                    CLIENT_GATEWAY_IP, CLIENT_PORT
                )
                asyncio.create_task(self.network.listen_for_packets(CLIENT_PORT))

            loop.run_until_complete(startup())
            loop.run_forever()

        thread = threading.Thread(target=network_worker, daemon=True)
        thread.start()
        self.append_chat("[SYSTEM] Network thread started", "system")

    def _get_loop(self):
        self._loop_ready.wait(timeout=10)
        return self.network_loop

    def _poll_queue(self):
        try:
            while True:
                event = self.ui_queue.get_nowait()
                self._handle_network_event(event)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._poll_queue)

    def _handle_network_event(self, event):
        event_type = event.get("type")

        if event_type == "log":
            self.append_chat(f"[LOG] {event['text']}", "system")

        elif event_type == "message":
            peer = event["peer"][:16]
            text = event["text"]
            self.append_chat(f"[PEER {peer}] {text}", "received")

        elif event_type == "ack":
            peer = event["peer"][:16]
            self.append_chat(
                f"[HANDSHAKE] ACK from {peer} — session active", "handshake"
            )
            self.update_status("Session Active")

        elif event_type == "error":
            self.append_chat(f"[ERROR] {event['text']}", "error")

        elif event_type == "file_received":
            fname = event["filename"]
            size = event["size"]
            path = event["path"]
            self.append_chat(
                f"[FILE] Received {fname} ({size} bytes) → {path}", "received"
            )

    def update_status(self, text):
        self.status_label.config(text=f"Status: {text}")

    def append_chat(self, text, tag="system"):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, text + "\n", tag)
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)

    def initiate_handshake(self):
        peer_pubkey = self.peer_entry.get().strip()
        if not peer_pubkey:
            messagebox.showwarning("Warning", "Enter peer's Ed25519 public key")
            return

        self.current_peer = peer_pubkey
        self.append_chat(
            f"[HANDSHAKE] Initiating to {peer_pubkey[:16]}...", "handshake"
        )

        loop = self._get_loop()
        if loop is None:
            self.append_chat("[ERROR] Network not ready", "error")
            return

        asyncio.run_coroutine_threadsafe(
            self.network.initiate_connection(peer_pubkey), loop
        )

    def send_message(self):
        text = self.message_entry.get().strip()
        if not text:
            return

        if not self.current_peer:
            messagebox.showwarning("Warning", "Connect to a peer first")
            return

        loop = self._get_loop()
        if loop is None:
            self.append_chat("[ERROR] Network not ready", "error")
            return

        self.append_chat(f"[YOU] {text}", "sent")
        self.message_entry.delete(0, tk.END)

        asyncio.run_coroutine_threadsafe(
            self.network.send_chat_message(text, self.current_peer), loop
        )

    def send_file(self):
        if not self.current_peer:
            messagebox.showwarning("Warning", "Connect to a peer first")
            return

        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        loop = self._get_loop()
        if loop is None:
            self.append_chat("[ERROR] Network not ready", "error")
            return

        self.append_chat(f"[FILE] Queuing {os.path.basename(filepath)}...", "system")

        asyncio.run_coroutine_threadsafe(
            self.network.send_file(filepath, self.current_peer), loop
        )


def main():
    root = tk.Tk()
    app = I2I2IClient(root)
    root.mainloop()


if __name__ == "__main__":
    main()
