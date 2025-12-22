import base64
import json
import requests
from cryptography.fernet import Fernet
from config.loader import ConfigLoader

class DataHandler:
    def __init__(self):
        config = ConfigLoader.load_config()
        self.encryption_key = config["encryption"]["key"]
        self.remote_url = config["storage"]["remote"]["url"]
        self.auth_token = config["storage"]["remote"]["auth_token"]
        self.fernet = None

    def enable_encryption(self):
        self.fernet = Fernet(base64.b64decode(self.encryption_key))

    def encrypt_data(self, data):
        if not self.fernet:
            raise RuntimeError("Encryption not enabled.")
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data):
        if not self.fernet:
            raise RuntimeError("Encryption not enabled.")
        return self.fernet.decrypt(encrypted_data.encode()).decode()

    def remote_log(self, data):
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        payload = {"log_data": data}

        try:
            response = requests.post(self.remote_url, json=payload, headers=headers)
            response.raise_for_status()
            print("Remote log sent successfully.")
        except requests.RequestException as e:
            print(f"Failed to send remote log: {e}")
