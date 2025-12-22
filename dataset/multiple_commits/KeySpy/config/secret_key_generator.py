from cryptography.fernet import Fernet
import base64
import json

def generate_and_encrypt_key(config_path="config/config.json"):
    # Generate an encryption key for secure storage
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    sample_key = Fernet.generate_key()  # Sample key to encrypt

    # Encrypt sample key and encode it in base64 for JSON compatibility
    encrypted_key = base64.b64encode(cipher_suite.encrypt(sample_key)).decode()

    # Load current config and update with encrypted key
    with open(config_path, "r") as file:
        config = json.load(file)

    config["encryption"]["key"] = encrypted_key

    with open(config_path, "w") as file:
        json.dump(config, file, indent=4)
    
    print(f"Encryption key saved. Store this key securely: {key.decode()}")

if __name__ == "__main__":
    generate_and_encrypt_key()
