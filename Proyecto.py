import socket
from scapy.all import ARP, Ether, srp

#PASO 1 REALIZADO

def get_mac_address(ip):
    try:
        # Crear una solicitud ARP para obtener la dirección MAC
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        # Enviar la solicitud y recibir la respuesta
        response = srp(arp_request, timeout=3, verbose=False)[0]
        # Extraer la dirección MAC de la respuesta
        mac_address = response[0][1].hwsrc
        return mac_address
    except Exception as e:
        print("Error al obtener la dirección MAC:", e)
        return None

def main():
    # Solicitar la dirección IP al usuario
    remote_ip = input("Introduce la dirección IP del otro equipo: ")

    # Obtener la dirección MAC del otro equipo
    remote_mac = get_mac_address(remote_ip)
    if remote_mac:
        print(f"La dirección MAC del otro equipo ({remote_ip}) es: {remote_mac}")
    else:
        print("No se pudo obtener la dirección MAC del otro equipo.")

if __name__ == "__main__":
    main()

#PASO 2 EN DESARROLLO

def send_message_or_file(ip, port):
    try:
        # Crear un socket TCP/IP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Conectar al otro equipo
            s.connect((ip, port))
            
            # Solicitar al usuario que ingrese un mensaje o elija un archivo
            choice = input("¿Deseas enviar un mensaje o un archivo? (mensaje/archivo): ").lower()
            
            if choice == "mensaje":
                # Capturar un mensaje del usuario
                message = input("Ingresa tu mensaje: ")
                # Codificar el mensaje como bytes y enviarlo
                s.sendall(message.encode())
            elif choice == "archivo":
                # Solicitar al usuario que ingrese la ruta del archivo
                filepath = input("Ingresa la ruta del archivo: ")
                # Leer el contenido del archivo
                with open(filepath, "rb") as file:
                    file_data = file.read()
                # Enviar los datos del archivo
                s.sendall(file_data)
            else:
                print("Opción no válida.")
            
            print("Mensaje/archivo enviado con éxito.")
    except Exception as e:
        print("Error al enviar el mensaje/archivo:", e)

def main():
    # Solicitar la dirección IP del otro equipo
    ip = input("Ingresa la dirección IP del otro equipo: ")
    # Especificar el puerto de destino
    port = 12345  # Puedes elegir cualquier puerto que desees, siempre que no esté siendo utilizado

    # Enviar el mensaje o el archivo al otro equipo
    send_message_or_file(ip, port)

if __name__ == "__main__":
    main()
