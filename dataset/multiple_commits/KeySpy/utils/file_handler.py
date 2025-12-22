import os
import logging
from utils.encryption import EncryptionUtils

class FileHandler:
    def __init__(self, encryption_enabled=False):
        self.logger = logging.getLogger("FileHandler")
        self.encryption = EncryptionUtils() if encryption_enabled else None

    def write_file(self, file_path: str, data: str, binary=False):
        mode = 'wb' if binary else 'w'
        try:
            with open(file_path, mode) as file:
                content = self.encryption.encrypt_data(data) if self.encryption else data
                file.write(content.encode() if binary else content)
            self.logger.info(f"Data written to {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to write to {file_path}: {e}")
            raise IOError(f"File write error: {e}")

    def read_file(self, file_path: str, binary=False) -> str:
        mode = 'rb' if binary else 'r'
        try:
            with open(file_path, mode) as file:
                content = file.read()
                if binary:
                    content = content.decode()
                return self.encryption.decrypt_data(content) if self.encryption else content
        except Exception as e:
            self.logger.error(f"Failed to read from {file_path}: {e}")
            raise IOError(f"File read error: {e}")
