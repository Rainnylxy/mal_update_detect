import json

def stocker_action_parametres(action, parametres):
    # Créer un dictionnaire pour stocker l'action et les paramètres
    action_parametres = {'action': action, 'parametres': parametres}

    # Convertir le dictionnaire en chaîne JSON
    chaine_json = json.dumps(action_parametres)

    # Retourner la chaîne JSON
    return chaine_json

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

# Exemple d'utilisation
action = "ddos"
parametres = {'ip': '172.76.32.12', 'protocole': 'udp'}

# Stocker l'action et les paramètres sous forme de chaîne JSON
chaine_stockee = stocker_action_parametres(action, parametres)

print("Chaine stockée:", chaine_stockee)

# Récupérer l'action et les paramètres à partir de la chaîne JSON
action_recuperee, parametres_recuperes = recuperer_action_parametres(chaine_stockee)

print("Action récupérée:", action_recuperee)
print("Paramètres récupérés:", parametres_recuperes)
