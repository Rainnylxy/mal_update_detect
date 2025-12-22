import json
import os
import base64
from pathlib import Path
from cryptography.fernet import Fernet

class ConfigLoader:
    _config = {}
    
    @classmethod
    def load_config(cls, path="config/config.json"):
        try:
            with open(path, "r") as config_file:
                cls._config = json.load(config_file)
            cls._apply_environment_overrides()
            cls._decrypt_sensitive_data()
            return cls._config
        except FileNotFoundError:
            raise RuntimeError("Configuration file not found.")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Configuration file is invalid JSON: {e}")
    
    @classmethod
    def _apply_environment_overrides(cls):
        # Allow environment-based overrides (e.g., development, production, testing)
        env = os.getenv("APP_ENV", cls._config.get("environment", "development"))
        cls._config["environment"] = env
        print(f"Environment set to: {env}")

    @classmethod
    def _decrypt_sensitive_data(cls):
        # Decrypt sensitive fields if encryption is enabled
        if cls._config["encryption"]["enabled"]:
            key = os.getenv("ENCRYPTION_KEY")
            if not key:
                raise RuntimeError("ENCRYPTION_KEY environment variable not set.")
            
            fernet = Fernet(key.encode())
            encrypted_key = cls._config["encryption"]["key"]
            cls._config["encryption"]["key"] = fernet.decrypt(
                base64.b64decode(encrypted_key)).decode()
    
    @classmethod
    def get(cls, key, default=None):
        # Retrieve config values with a fallback default
        return cls._config.get(key, default)
