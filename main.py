import os
import random
import socket
import threading
import json
from tkinter import *
from tkinter import ttk, messagebox, filedialog
from cryptography.hazmat.primitives.asymmetric.ed25519 \
    import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from pybulletproofs import zkrp_verify, zkrp_prove

class FileSharingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Sharing with Digital Signatures")
        self.root.geometry("900x700")

        self.host = 'localhost'
        self.port = 5000
        self.server_socket = None
        self.client_socket = None
        self.connections = []

        self.private_key = None
        self.public_key = None
        self.signature = None
        self.proof = None
        self.received_files = []

        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=BOTH, expand=True)

        network_frame = ttk.LabelFrame(main_frame, text="Network Settings", padding="10")
        network_frame.pack(fill=X, pady=5)

        ttk.Label(network_frame, text="Host:").grid(row=0, column=0, sticky=W)
        self.host_entry = ttk.Entry(network_frame, width=20)
        self.host_entry.grid(row=0, column=1, padx=5, pady=5, sticky=W)
        self.host_entry.insert(0, self.host)

        ttk.Label(network_frame, text="Port:").grid(row=0, column=2, sticky=W)
        self.port_entry = ttk.Entry(network_frame, width=10)
        self.port_entry.grid(row=0, column=3, padx=5, pady=5, sticky=W)
        self.port_entry.insert(0, str(self.port))

        ttk.Button(network_frame, text="Start Server", command=self.start_server).grid(row=0, column=4, padx=5)
        ttk.Button(network_frame, text="Connect", command=self.connect_to_server).grid(row=0, column=5, padx=5)

        file_frame = ttk.LabelFrame(main_frame, text="File Operations", padding="10")
        file_frame.pack(fill=X, pady=5)

        ttk.Label(file_frame, text="File:").grid(row=0, column=0, sticky=W)
        self.file_entry = ttk.Entry(file_frame, width=50)
        self.file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=5)

        ttk.Label(file_frame, text="Value (0-255):").grid(row=1, column=0, sticky=W)
        self.value_entry = ttk.Entry(file_frame, width=10)
        self.value_entry.grid(row=1, column=1, padx=5, pady=5, sticky=W)
        self.value_entry.insert(0, str(random.randint(0, 255)))

        ttk.Label(file_frame, text="Bit Length:").grid(row=1, column=2, sticky=W)
        self.bit_length_combobox = ttk.Combobox(file_frame, values=[8, 16, 32], width=5)
        self.bit_length_combobox.grid(row=1, column=3, padx=5, pady=5, sticky=W)
        self.bit_length_combobox.current(0)

        ttk.Button(file_frame, text="Sign & Send", command=self.sign_and_send).grid(row=2, column=0, columnspan=4, pady=5)

        self.received_frame = ttk.LabelFrame(main_frame, text="Received Files", padding="10")
        self.received_frame.pack(fill=BOTH, expand=True)

        self.tree = ttk.Treeview(self.received_frame, columns=("Filename", "Signature", "Proof", "Valid"),
                                 show="headings")
        self.tree.heading("Filename", text="Filename")
        self.tree.heading("Signature", text="Signature Valid")
        self.tree.heading("Proof", text="Proof Valid")
        self.tree.heading("Valid", text="Overall Valid")
        self.tree.pack(fill=BOTH, expand=True)

        ttk.Button(self.received_frame, text="Verify Selected", command=self.verify_selected).pack(pady=5)

        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="10")
        log_frame.pack(fill=X, pady=5)

        self.log_text = Text(log_frame, height=8, wrap=WORD)
        scrollbar = ttk.Scrollbar(log_frame, orient=VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=RIGHT, fill=Y)
        self.log_text.pack(fill=BOTH, expand=True)

        self.listening_thread = threading.Thread(target=self.listen_for_files, daemon=True)
        self.listening_thread.start()

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_entry.delete(0, END)
            self.file_entry.insert(0, filename)

    def start_server(self):
        self.host = self.host_entry.get()
        self.port = int(self.port_entry.get())

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.log_message(f"Server started on {self.host}:{self.port}")
        except Exception as e:
            self.log_message(f"Error starting server: {str(e)}")

    def connect_to_server(self):
        self.host = self.host_entry.get()
        self.port = int(self.port_entry.get())

        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            self.log_message(f"Connected to server at {self.host}:{self.port}")
        except Exception as e:
            self.log_message(f"Error connecting to server: {str(e)}")

    def sign_and_send(self):
        filename = self.file_entry.get()
        if not filename or not os.path.exists(filename):
            messagebox.showerror("Error", "Please select a valid file")
            return
        try:
            with open(filename, 'rb') as file:
                file_data = file.read()
            value = int(self.value_entry.get())
            bit_length = int(self.bit_length_combobox.get())

            self.private_key = Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
            self.signature = self.private_key.sign(file_data)

            self.proof = zkrp_prove(int(value), bit_length)
            pub_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            data_to_send = {
                'filename': os.path.basename(filename),
                'file_data': file_data.hex(),
                'public_key': pub_key_bytes.hex(),
                'signature': self.signature.hex(),
                'proof': [str(p) for p in self.proof],
                'value': value,
                'bit_length': bit_length
            }
            if self.client_socket:
                self.client_socket.sendall(json.dumps(data_to_send).encode())
                self.log_message(f"File {filename} sent with signature and proof")
            else:
                messagebox.showerror("Error", "Not connected to any server")
        except Exception as e:
            self.log_message(f"Error sending file: {str(e)}")

    def listen_for_files(self):
        while True:
            try:
                if self.server_socket:
                    conn, addr = self.server_socket.accept()
                    self.log_message(f"Connection from {addr}")
                    threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()
            except:
                pass
    def handle_client(self, conn):
        try:
            data = conn.recv(1024 * 1024)  # Max 1MB
            if not data:
                return
            received_data = json.loads(data.decode())

            received_data['file_data'] = bytes.fromhex(received_data['file_data'])
            received_data['public_key'] = bytes.fromhex(received_data['public_key'])
            received_data['signature'] = bytes.fromhex(received_data['signature'])
            received_data['proof'] = [int(p) for p in received_data['proof']]

            public_key = Ed25519PublicKey.from_public_bytes(received_data['public_key'])
            try:
                public_key.verify(received_data['signature'], received_data['file_data'])
                signature_valid = True
            except InvalidSignature:
                signature_valid = False

            proof_valid = zkrp_verify(
                received_data['proof'][0],
                received_data['proof'][1],
                received_data['bit_length']
            )
            save_dir = os.path.join(os.getcwd(), "received_files")
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, received_data['filename'])

            with open(save_path, 'wb') as file:
                file.write(received_data['file_data'])

            self.received_files.append({
                'path': save_path,
                'data': received_data,
                'signature_valid': signature_valid,
                'proof_valid': proof_valid
            })

            self.root.after(0, self.update_received_files)
            self.log_message(f"Received file: {received_data['filename']}")
        except Exception as e:
            self.log_message(f"Error handling client: {str(e)}")
        finally:
            conn.close()

    def update_received_files(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for i, file_info in enumerate(self.received_files):
            filename = os.path.basename(file_info['path'])
            sig_valid = "Yes" if file_info['signature_valid'] else "No"
            proof_valid = "Yes" if file_info['proof_valid'] else "No"
            overall_valid = "Yes" if file_info['signature_valid'] and file_info['proof_valid'] else "No"

            self.tree.insert("", "end", values=(filename, sig_valid, proof_valid, overall_valid))
    def verify_selected(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select a file to verify")
            return

        item = self.tree.item(selected_item)
        filename = item['values'][0]

        file_info = next((f for f in self.received_files if os.path.basename(f['path']) == filename), None)

        if file_info:
            result = f"Verification results for {filename}:\n"
            result += f"Signature valid: {'Yes' if file_info['signature_valid'] else 'No'}\n"
            result += f"Range proof valid: {'Yes' if file_info['proof_valid'] else 'No'}\n"
            result += f"Value: {file_info['data']['value']}\n"
            result += f"Bit length: {file_info['data']['bit_length']}"

            messagebox.showinfo("Verification Results", result)
        else:
            messagebox.showerror("Error", "File not found")

    def log_message(self, message):
        self.log_text.insert(END, message + "\n")
        self.log_text.see(END)

    def on_closing(self):
        if self.server_socket:
            self.server_socket.close()
        if self.client_socket:
            self.client_socket.close()
        self.root.destroy()


if __name__ == "__main__":
    root = Tk()
    app = FileSharingApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()