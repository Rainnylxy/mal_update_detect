from Crypto.PublicKey import RSA

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding




def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

def crypt_file(path, public_key):
    try:
        with open(path, 'r') as file:
            plaintext = file.read()
            encrypted_text=encrypt_message(plaintext, public_key)
        with open(path + "_encrypted", 'w') as encrypted_file:
            encrypted_file.write(encrypted_text)

        print("Encryption successful.")
    except Exception as e:
        print(f"Error: {e}")

# Générer une paire de clés (peut être fait une seule fois)

key = RSA.generate(1024)
    #chiffrage
public_key = key.publickey()
private_key = key

# Crypter un message avec la clé publique
# Exemple d'utilisation
path = "chemin\versle\fichier.txt"
ciphertext = crypt_file(path, public_key)
print("Encrypted message:", ciphertext)

# Décrypter le message avec la clé privée
decrypted_message = decrypt_message(ciphertext, private_key)
print("Decrypted message:", decrypted_message)
