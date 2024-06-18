import tkinter as tk
from tkinter import simpledialog, filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA384, SHA512, BLAKE2b
import hashlib
import requests
import subprocess
import re
import base64

class CryptoAppSender:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto App - Envío")
        self.root.geometry("800x600")

        self.public_key = None
        self.private_key = RSA.generate(2048)
        self.file_path = None
        self.encrypted_message = None

        self.create_widgets()
    
    def create_widgets(self):
        self.label = tk.Label(self.root, text="Crypto App - Envío")
        self.label.pack()

        self.request_key_button = tk.Button(self.root, text="Solicitar llave pública", command=self.request_public_key)
        self.request_key_button.pack()

        self.select_file_button = tk.Button(self.root, text="Seleccionar archivo", command=self.select_file)
        self.select_file_button.pack()

        self.hash_label = tk.Label(self.root, text="SHA384: ")
        self.hash_label.pack()

        self.hash_button = tk.Button(self.root, text="Generar HASH SHA384", command=self.generate_sha384_hash)
        self.hash_button.pack()

        self.encrypt_button = tk.Button(self.root, text="Encriptar mensaje", command=self.encrypt_message)
        self.encrypt_button.pack()

        self.hash_encrypted_label = tk.Label(self.root, text="SHA512: ")
        self.hash_encrypted_label.pack()

        self.hash_encrypted_button = tk.Button(self.root, text="Generar HASH SHA512", command=self.generate_sha512_hash)
        self.hash_encrypted_button.pack()

        self.steg_button = tk.Button(self.root, text="Seleccionar archivo para esconder mensaje", command=self.steganography)
        self.steg_button.pack()

        self.hash_blake2_label = tk.Label(self.root, text="BLAKE2: ")
        self.hash_blake2_label.pack()

        self.hash_blake2_button = tk.Button(self.root, text="Generar HASH Blake2", command=self.generate_blake2_hash)
        self.hash_blake2_button.pack()

        self.send_button = tk.Button(self.root, text="Enviar mensaje", command=self.send_message)
        self.send_button.pack()
    
    def request_public_key(self):
        ip = simpledialog.askstring("Input", "Ingrese la IP del otro equipo:")
        if not ip:
            messagebox.showerror("Error", "Debe ingresar una IP")
            return
        
        # Obtener la dirección MAC de la IP
        mac_address = self.get_mac_address(ip)
        if not mac_address:
            messagebox.showerror("Error", "No se pudo obtener la dirección MAC")
            return

        messagebox.showinfo("Dirección MAC", f"Dirección MAC obtenida: {mac_address}")

        # Solicitar la llave pública
        try:
            # Mostrar mensaje de estado
            messagebox.showinfo("Estado", f"Intentando conectar a {ip}")
            response = requests.get(f"http://{ip}/get_public_key", timeout=10)
            response.raise_for_status()
            self.public_key = RSA.import_key(response.content)
            messagebox.showinfo("Llave pública recibida", "La llave pública ha sido recibida con éxito.")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"No se pudo obtener la llave pública: {e}")
    
    def get_mac_address(self, ip):
        try:
            # Ejecutar el comando arp -a
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            arp_output = result.stdout

            # Buscar la línea que contiene la IP
            for line in arp_output.splitlines():
                if ip in line:
                    # Buscar la dirección MAC en la línea
                    mac_address = re.search(r'([a-fA-F0-9]{2}[:-]){5}[a-fA-F0-9]{2}', line)
                    if mac_address:
                        return mac_address.group(0)
            return None
        except Exception as e:
            messagebox.showerror("Error", f"Error obteniendo la dirección MAC: {e}")
            return None
    
    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            messagebox.showinfo("Archivo seleccionado", f"Archivo seleccionado: {self.file_path}")
        else:
            messagebox.showerror("Error", "No se ha seleccionado un archivo.")
    
    def generate_sha384_hash(self):
        if not self.file_path:
            messagebox.showerror("Error", "No se ha seleccionado un archivo.")
            return
        
        with open(self.file_path, "rb") as file:
            message = file.read()

        self.sha384_hash = hashlib.sha384(message).hexdigest()
        self.hash_label.config(text=f"SHA384: {self.sha384_hash}")

    def encrypt_message(self):
        if not self.file_path:
            messagebox.showerror("Error", "No se ha seleccionado un archivo.")
            return

        with open(self.file_path, "rb") as file:
            message = file.read()

        # Generar clave AES
        aes_key = get_random_bytes(32)
        self.cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        self.ciphertext, self.tag = self.cipher_aes.encrypt_and_digest(message)

        # Encriptar la clave AES con RSA
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        self.encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        
        messagebox.showinfo("Mensaje encriptado", "El mensaje ha sido encriptado con éxito.")
    
    def generate_sha512_hash(self):
        if not self.ciphertext:
            messagebox.showerror("Error", "No se ha encriptado un mensaje.")
            return

        self.sha512_hash = hashlib.sha512(self.ciphertext).hexdigest()
        self.hash_encrypted_label.config(text=f"SHA512: {self.sha512_hash}")

    def steganography(self):
        if not self.ciphertext:
            messagebox.showerror("Error", "No se ha encriptado un mensaje.")
            return

        self.steg_file = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png"), ("All files", "*.*")])
        if self.steg_file:
            with open(self.steg_file, "wb") as f:
                f.write(self.ciphertext)
            messagebox.showinfo("Esteganografía", "El mensaje ha sido escondido en el archivo seleccionado.")

    def generate_blake2_hash(self):
        if not self.ciphertext:
            messagebox.showerror("Error", "No se ha encriptado un mensaje.")
            return

        self.blake2_hash = BLAKE2b.new(data=self.ciphertext).hexdigest()
        self.hash_blake2_label.config(text=f"BLAKE2: {self.blake2_hash}")

    def send_message(self):
        if not self.ciphertext or not self.steg_file:
            messagebox.showerror("Error", "No se ha encriptado un mensaje o no se ha seleccionado un archivo para esconder el mensaje.")
            return
        
        ip = simpledialog.askstring("Input", "Ingrese la IP del otro equipo para enviar el mensaje:")
        try:
            files = {'file': open(self.steg_file, 'rb')}
            data = {
                'sha384_hash': self.sha384_hash,
                'sha512_hash': self.sha512_hash,
                'blake2_hash': self.blake2_hash,
                'encrypted_aes_key': base64.b64encode(self.encrypted_aes_key).decode('utf-8'),
                'nonce': base64.b64encode(self.cipher_aes.nonce).decode('utf-8'),
                'tag': base64.b64encode(self.tag).decode('utf-8')
            }
            response = requests.post(f"http://{ip}/upload", files=files, data=data)
            if response.status_code == 200:
                messagebox.showinfo("Éxito", "Mensaje enviado con éxito.")
            else:
                messagebox.showerror("Error", "No se pudo enviar el mensaje.")
        except requests.RequestException as e:
            messagebox.showerror("Error", f"No se pudo enviar el mensaje: {e}")

root = tk.Tk()
app = CryptoAppSender(root)
root.mainloop()
