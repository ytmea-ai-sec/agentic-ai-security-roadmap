## 2. Pratique & TP sous Termux

"""Mets-toi dans le bon dossier sous Termux :

```bash
cd ~/AI_Security_Engineer/Phase_1_Bases_sur_tablette_Termux_Hygiène_IA/Chapitre_4_Fichiers_Logs_et_Analyse_Reseau

```

*(Si le dossier n'existe pas encore, crée-le avec `mkdir -p`)*.
---"""

### Étape A : Créer un faux fichier de Log d'attaque

"""Nous allons simuler un fichier de log d'un serveur Web Nginx.
Crée le fichier `server.log` avec `nano server.log` et colle ce contenu :
```text
192.168.1.10 - [20/Sep/2026:10:00:01] "GET /index.html HTTP/1.1" 200
10.0.0.45 - [20/Sep/2026:10:00:05] "GET /admin HTTP/1.1" 403
192.168.1.99 - [20/Sep/2026:10:01:12] "POST /login HTTP/1.1" 401
192.168.1.99 - [20/Sep/2026:10:01:14] "POST /login HTTP/1.1" 401
192.168.1.99 - [20/Sep/2026:10:01:16] "POST /login HTTP/1.1" 401
192.168.1.99 - [20/Sep/2026:10:01:18] "POST /login HTTP/1.1" 200
10.0.0.12 - [20/Sep/2026:10:02:00] "GET /images/logo.png HTTP/1.1" 200

```

---"""

### Étape B : Script d'analyse de logs en Python (`log_analyzer.py`)

"""Crée le fichier `log_analyzer.py` avec `nano` et recopie ce code structuré (Anglais pour la logique, Français pour
l'affichage) :

```python"""

import os

def parse_log_file(file_path):
    """Reads a log file and extracts suspicious IP addresses."""
    if not os.path.exists(file_path):
        print(f"[!] Erreur : Le fichier {file_path} est introuvable.")
        return []

    failed_login_ips = []

    try:
        with open(file_path, "r") as file:
            for line in file:
                # Detection of failed HTTP logins (Status 401)
                if "POST /login" in line and "401" in line:
                    ip_address = line.split(" ")[0]
                    failed_login_ips.append(ip_address)

        return failed_login_ips

    except IOError:
        print("[!] Erreur lors de la lecture du fichier de log.")
        return []

def generate_security_report(suspicious_ips):
    """Generates a summary report of suspicious activity."""
    print("=== ANALYSEUR DE LOGS DE SÉCURITÉ ===")
    
    if not suspicious_ips:
        print("[+] Aucune activité suspecte détectée.")
        return

    # Count occurrences per IP
    ip_counts = {}
    for ip in suspicious_ips:
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    print(f"[!] Tentatives de connexion échouées détectées :")
    for ip, count in ip_counts.items():
        print(f"    - IP: {ip} | Échecs: {count}")
        if count >= 3:
            print(f"      [ALERT] Attaque par Force Brute suspectée depuis {ip} !")

    # Save alert to file
    try:
        with open("security_alerts.txt", "w") as alert_file:
            alert_file.write("=== LOG ANALYSIS ALERTS ===\n")
            for ip, count in ip_counts.items():
                alert_file.write(f"IP: {ip} - Failed Logins: {count}\n")
        print("\n[+] Rapport d'alerte sauvegardé dans 'security_alerts.txt'.")
    except IOError:
        print("[!] Erreur lors de l'écriture du rapport d'alerte.")

if __name__ == "__main__":
    log_file = "server.log"
    suspicious_data = parse_log_file(log_file)
    generate_security_report(suspicious_data)
