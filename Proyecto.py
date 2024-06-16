import tkinter as tk
from tkinter import simpledialog, filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA384, SHA512, BLAKE2b
import hashlib
import requests
import subprocess
import re

class CryptoAppSender:
    def __init__(self, root):
        self.root = root
        self.root.title("Crypto App - Envío")
        self.root.geometry("800x600")

        self.public_key = None
        self.private_key = RSA.generate(2048)

        self.create_widgets()
    
    def create_widgets(self):
        self.label = tk.Label(self.root, text="Crypto App - Envío")
        self.label.pack()

        self.request_key_button = tk.Button(self.root, text="Solicitar llave pública", command=self.request_public_key)
        self.request_key_button.pack()

        self.select_file_button = tk.Button(self.root, text="Seleccionar archivo", command=self.select_file)
        self.select_file_button.pack()

        self.hash_label = tk.Label(self.root, text="")
        self.hash_label.pack()

        self.encrypt_button = tk.Button(self.root, text="Encriptar y enviar", command=self.encrypt_and_send)
        self.encrypt_button.pack()
    
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
        messagebox.showinfo("Archivo seleccionado", f"Archivo seleccionado: {self.file_path}")

    def encrypt_and_send(self):
        with open(self.file_path, "rb") as file:
            message = file.read()

        # Paso 3: Generar el HASH en sha384 del mensaje
        sha384_hash = hashlib.sha384(message).hexdigest()
        self.hash_label.config(text=f"SHA384: {sha384_hash}")

        # Paso 4: Encriptar el mensaje con RSA inverso
        cipher = PKCS1_OAEP.new(self.public_key)
        encrypted_message = cipher.encrypt(message)

        # Paso 5: Generar el HASH sha512 del mensaje encriptado
        sha512_hash = hashlib.sha512(encrypted_message).hexdigest()

        # Paso 6: Opción de esteganografía y Paso 7: Generar el HASH Blake2
        steg_file = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png"), ("All files", "*.*")])
        if steg_file:
            with open(steg_file, "wb") as f:
                f.write(encrypted_message)
            blake2_hash = BLAKE2b.new(data=encrypted_message).hexdigest()
            messagebox.showinfo("BLAKE2 Hash", f"BLAKE2: {blake2_hash}")

            # Paso 8: Enviar el mensaje a otro equipo junto con los hashes
            ip = simpledialog.askstring("Input", "Ingrese la IP del otro equipo para enviar el mensaje:")
            try:
                files = {'file': open(steg_file, 'rb')}
                data = {
                    'sha384_hash': sha384_hash,
                    'sha512_hash': sha512_hash,
                    'blake2_hash': blake2_hash
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
