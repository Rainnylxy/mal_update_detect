def to_string(liste):
    print("rentre dans la fonction to_string")
    string="["
    for index, item in enumerate(liste):
        string+=str(item)
        if index<len(liste)-1:
            string+=","
    return string +"]"


def tojson(tableau_multidimensionnel):
    
    print("tableau_multidimensionnel:",tableau_multidimensionnel)
    tabstr="{"
    for index,subtab in enumerate(tableau_multidimensionnel):
        tabstr+=to_string(subtab)
        
        if index < len(tableau_multidimensionnel) - 1:
            tabstr += ","

    tabstr += "}"
    print("tabstr:", tabstr)
    return tabstr

def json_to_tab(tabstr) :
    print("rentre dans la fonction json_to_tab")
    print("tabstr:",tabstr)
    # Supprimer les crochets extérieurs
    tabstr = tabstr[1:-1]
    # Diviser la chaîne en sous-chaînes représentant chaque sous-tableau
    sous_chaines = tabstr.split("],[")
    print("sous_chaines:",sous_chaines)
    # Créer une liste de sous-tableaux
    tableau = []
    for sous_chaine in sous_chaines:
        print("sous_chaine avant supr:",sous_chaine)
        # Supprimer les crochets string extérieurs
        sous_chaine = sous_chaine.replace("[", "")
        sous_chaine = sous_chaine.replace("]", "")
        print("sous_chaine apres supr:",sous_chaine)    
        # Créer une liste de nombres
        nombres = sous_chaine.split(",")
        print("nombres:",nombres)
        # Convertir les chaînes en nombres
        for index, nombre in enumerate(nombres):
            nombres[index] = int(nombre)
        # Ajouter la liste de nombres au tableau
        tableau.append(nombres)
        print("tableau:",tableau)

def fizz_buzz(n):
    for i in range(1, n + 1):
        if i % 3 == 0 and i % 7 == 0:
            print("FizzBuzz")
        elif i % 3 == 0:
            print("Fizz")
        elif i % 7 == 0:
            print("Buzz")
        else:
            print(i)
def sum_str(chaine):
    somme = 0
    for c in chaine.upper():
        if c.isalpha():
            valeurs = int(ord(c) - 64)
            somme +=valeurs
            print(somme)
    return somme       

sum_str("abc")   

tableau= [[9, 8, 7], [4, 5, 6], [3, 2, 1]]
#jsontab=tojson (tableau)
#json_to_tab(jsontab)

