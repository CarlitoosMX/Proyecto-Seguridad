import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA384, SHA512, BLAKE2b
import hashlib
import os
from flask import Flask, request
import socket
import base64

class CryptoAppReceiver:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto App - Recepción")
        self.root.geometry("800x600")

        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey().export_key()

        self.expected_sha384_hash = None
        self.expected_sha512_hash = None
        self.expected_blake2_hash = None
        self.encrypted_aes_key = None
        self.nonce = None
        self.tag = None

        self.create_widgets()
        self.setup_server()
    
    def create_widgets(self):
        self.label = tk.Label(self.root, text="Crypto App - Recepción")
        self.label.pack()

        self.receive_button = tk.Button(self.root, text="Recibir y desencriptar", command=self.receive_and_decrypt)
        self.receive_button.pack()
    
    def setup_server(self):
        app = Flask(__name__)

        @app.route('/get_public_key', methods=['GET'])
        def get_public_key():
            return self.public_key

        @app.route('/upload', methods=['POST'])
        def upload():
            file = request.files['file']
            file.save("received_message.png")

            self.expected_sha384_hash = request.form['sha384_hash']
            self.expected_sha512_hash = request.form['sha512_hash']
            self.expected_blake2_hash = request.form['blake2_hash']
            self.encrypted_aes_key = base64.b64decode(request.form['encrypted_aes_key'])
            self.nonce = base64.b64decode(request.form['nonce'])
            self.tag = base64.b64decode(request.form['tag'])
            
            messagebox.showinfo("Mensaje recibido", "El mensaje ha sido recibido.")
            return "Archivo recibido", 200

        local_ip = self.get_local_ip()
        print(f"Servidor corriendo en IP: {local_ip}")
        app.run(host=local_ip, port=80)

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    def receive_and_decrypt(self):
        try:
            with open("received_message.png", "rb") as file:
                received_encrypted_message = file.read()

            blake2_hash = BLAKE2b.new(data=received_encrypted_message).hexdigest()
            if blake2_hash != self.expected_blake2_hash:
                messagebox.showerror("Error", "Comunicación alterada")
                os.remove("received_message.png")
                return

            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            aes_key = cipher_rsa.decrypt(self.encrypted_aes_key)

            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=self.nonce)
            decrypted_message = cipher_aes.decrypt_and_verify(received_encrypted_message, self.tag)

            sha512_hash = hashlib.sha512(received_encrypted_message).hexdigest()
            if sha512_hash != self.expected_sha512_hash:
                messagebox.showerror("Error", "SHA512 hash incorrecto")
                return

            sha384_hash = hashlib.sha384(decrypted_message).hexdigest()
            if sha384_hash == self.expected_sha384_hash:
                messagebox.showinfo("Éxito", "El mensaje es correcto")
            else:
                messagebox.showerror("Error", "SHA384 hash incorrecto")

        except Exception as e:
            messagebox.showerror("Error", f"Error durante la recepción: {e}")

root = tk.Tk()
app = CryptoAppReceiver(root)
root.mainloop()
