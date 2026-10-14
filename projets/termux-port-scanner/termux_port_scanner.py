import socket
import sys

# --- ANGLAIS : Moteur logique et Fonctions ---

def get_target_ip(target_host):
    """Resolves target hostname to IP address."""
    try:
        ip_address = socket.gethostbyname(target_host)
        return ip_address
    except socket.gaierror:
        # FRANÇAIS : Message à l'écran
        print("[!] Erreur : Impossible de résoudre le nom d'hôte ou l'IP.")
        return None

def check_port(target_ip, port):
    """Scans a single TCP port and handles socket timeouts."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target_ip, port))
        s.close()
        return result == 0
    except socket.error:
        return False

def evaluate_port_risk(port):
    """Evaluates port risk level based on standard services."""
    high_risk_ports = [21, 22, 23, 445, 3389]
    if port in high_risk_ports:
        return "CRITIQUE"
    return "NORMAL"

def run_scanner():
    """Main scanner logic."""
    print("=== SCANNER DE PORTS TERMUX v1.0 ===")

    # FRANÇAIS : Interaction utilisateur
    target = input("Entrez l'IP ou le nom de domaine cible (ex: scanme.nmap.org) : ")

    target_ip = get_target_ip(target)
    if not target_ip:
        return

    try:
        start_port = int(input("Port de début (ex: 20) : "))
        end_port = int(input("Port de fin (ex: 90) : "))
    except ValueError:
        print("[!] Erreur : Les ports doivent être des nombres entiers.")
        return

    print(f"\n[+] Scan de la cible : {target_ip}")
    print(f"[+] Plage de ports : {start_port} à {end_port}\n")

    open_ports = []

    try:
        for port in range(start_port, end_port + 1):
            if check_port(target_ip, port):
                risk = evaluate_port_risk(port)
                print(f"[+] Port {port} : OUVERT | Niveau de risque : {risk}")
                open_ports.append(port)

    except KeyboardInterrupt:
        print("\n[!] Scan interrompu par l'utilisateur (CTRL+C).")
        sys.exit()

    # Sauvegarde des résultats
    try:
        with open("scan_results.txt", "w") as file:
            file.write(f"Rapport de scan pour {target_ip}\n")
            file.write(f"Ports ouverts : {open_ports}\n")
        print("\n[+] Résultats sauvegardés dans 'scan_results.txt'.")
    except IOError:
        print("\n[!] Erreur lors de la sauvegarde du fichier.")

    print(f"[=] Scan terminé. {len(open_ports)} port(s) ouvert(s) trouvé(s).")

if __name__ == "__main__":
    run_scanner()
