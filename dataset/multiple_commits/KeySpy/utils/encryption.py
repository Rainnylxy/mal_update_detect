from cryptography.fernet import Fernet
import base64
import os
from config.loader import ConfigLoader

class EncryptionUtils:
    def __init__(self):
        config = ConfigLoader.load_config()
        key = config.get("encryption", {}).get("key")
        if not key:
            raise ValueError("Encryption key is not configured.")
        self.key = base64.urlsafe_b64encode(key.encode("utf-8"))
        self.cipher = Fernet(self.key)

    def encrypt_data(self, data: str) -> str:
        try:
            encrypted = self.cipher.encrypt(data.encode("utf-8"))
            return encrypted.decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to encrypt data: {e}")

    def decrypt_data(self, encrypted_data: str) -> str:
        try:
            decrypted = self.cipher.decrypt(encrypted_data.encode("utf-8"))
            return decrypted.decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to decrypt data: {e}")

    @staticmethod
    def generate_key() -> str:
        return Fernet.generate_key().decode("utf-8")

if __name__ == "__main__":
    print(f"Generated Key: {EncryptionUtils.generate_key()}")
