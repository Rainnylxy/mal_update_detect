import os
from pathlib import Path
from dotenv import load_dotenv, set_key

def setup_environment():
    env_path = Path(".env")
    load_dotenv(dotenv_path=env_path)

    default_vars = {
        "APP_ENV": "development",
        "ENCRYPTION_KEY": input("Enter your encryption key: "),
        "REMOTE_AUTH_TOKEN": input("Enter remote server auth token: ")
    }

    for key, value in default_vars.items():
        if not os.getenv(key):
            set_key(dotenv_path=env_path, key_to_set=key, value_to_set=value)
            print(f"{key} set in .env file.")
        else:
            print(f"{key} already set.")

    print("Environment variables setup complete.")

if __name__ == "__main__":
    setup_environment()
