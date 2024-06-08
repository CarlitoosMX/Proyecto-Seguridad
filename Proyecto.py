from scapy.all import ARP, Ether, srp

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
