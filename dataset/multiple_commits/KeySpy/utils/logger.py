import logging
import os
from config.loader import ConfigLoader

class LoggerUtils:
    @staticmethod
    def setup_logger(name: str) -> logging.Logger:
        config = ConfigLoader.load_config()
        log_level = config.get("logging", {}).get("level", "INFO").upper()
        log_file = config.get("logging", {}).get("file", "app.log")

        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, log_level, logging.INFO))

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        logger.info(f"Logger {name} initialized with level {log_level}")
        return logger
