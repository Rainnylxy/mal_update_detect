import os
from cryptography.fernet import Fernet
def decrypt():
    files = []
    for f in os.listdir():
        if (f == "main.py") or (f == "keyfile.key") or (f == "decrypt.py") or (f == "encrypt.py"):
            continue
        files.append(f)
        print(files)
    with open("keyfile.key", 'rb') as key_file:
        key = key_file.read()
    for file in files:
        with open(file, 'rb') as _file:
            contents = _file.read()
        contents_decrypted = Fernet(key).decrypt(contents)
        with open(file, 'wb') as _file:
            _file.write(contents_decrypted)
