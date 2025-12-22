import os

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

# Exemple d'utilisation
#dossier_courant = "C:\\Users\\david\\Desktop\\ippsi"
#fichiers_dossier_courant = lister_fichiers(dossier_courant)

#print(f"Fichiers dans le dossier courant ({dossier_courant}):")
#for fichier in fichiers_dossier_courant:
#    print(fichier)
print("dans listfile.py")   
