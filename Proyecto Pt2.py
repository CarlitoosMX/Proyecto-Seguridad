import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA384, SHA512, BLAKE2b
import hashlib
import os

class CryptoAppReceiver:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto App - Recepción")
        self.root.geometry("800x600")  # Establecer tamaño de la ventana a 800x600

        self.public_key = RSA.generate(2048).publickey().export_key()
        self.private_key = RSA.generate(2048)

        self.expected_sha384_hash = None
        self.expected_sha512_hash = None
        self.expected_blake2_hash = None

        self.create_widgets()
        self.setup_server()
    
    def create_widgets(self):
        self.label = tk.Label(self.root, text="Crypto App - Recepción")
        self.label.pack()

        self.receive_button = tk.Button(self.root, text="Recibir y desencriptar", command=self.receive_and_decrypt)
        self.receive_button.pack()
    
    def setup_server(self):
        # Simulación de servidor para recibir la llave pública y el archivo
        from flask import Flask, request, send_file

        app = Flask(__name__)

        @app.route('/get_public_key', methods=['GET'])
        def get_public_key():
            return self.public_key

        @app.route('/upload', methods=['POST'])
        def upload():
            file = request.files['file']
            file.save("received_message.png")
            self.expected_blake2_hash = BLAKE2b.new(data=file.read()).hexdigest()
            messagebox.showinfo("Mensaje recibido", "El mensaje ha sido recibido.")
            return "Archivo recibido", 200

        # Cambia la IP y el puerto para que Flask escuche en 192.168.100.18:80
        app.run(host='192.168.100.18', port=80)

    def receive_and_decrypt(self):
        try:
            with open("received_message.png", "rb") as file:
                received_encrypted_message = file.read()

            # Paso 9: Validar el HASH Blake2
            blake2_hash = BLAKE2b.new(data=received_encrypted_message).hexdigest()
            if blake2_hash != self.expected_blake2_hash:
                messagebox.showerror("Error", "Comunicación alterada")
                os.remove("received_message.png")
                return

            # Paso 10: Extraer el mensaje y eliminar el estego objeto
            decrypted_message = self.decrypt_message(received_encrypted_message)
            os.remove("received_message.png")
            if not decrypted_message:
                return

            # Paso 11: Validar el HASH sha512
            sha512_hash = hashlib.sha512(received_encrypted_message).hexdigest()
            if sha512_hash != self.expected_sha512_hash:
                messagebox.showerror("Error", "SHA512 hash incorrecto")
                return

            # Paso 12: Usar la llave privada para extraer el mensaje
            decrypted_message = self.decrypt_message(received_encrypted_message)

            # Paso 13: Validar el hash sha384
            sha384_hash = hashlib.sha384(decrypted_message).hexdigest()
            if sha384_hash == self.expected_sha384_hash:
                messagebox.showinfo("Éxito", "El mensaje es correcto")
            else:
                messagebox.showerror("Error", "SHA384 hash incorrecto")

        except Exception as e:
            messagebox.showerror("Error", f"Error durante la recepción: {e}")

    def decrypt_message(self, encrypted_message):
        cipher = PKCS1_OAEP.new(self.private_key)
        try:
            return cipher.decrypt(encrypted_message)
        except ValueError:
            messagebox.showerror("Error", "Desencriptación fallida")
            return None

root = tk.Tk()
app = CryptoAppReceiver(root)
root.mainloop()
