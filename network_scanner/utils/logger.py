import logging
import os
from datetime import datetime, timezone


class Logger:
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(log_dir, f"scan_{timestamp}.log")

        self.logger = logging.getLogger('NetworkScanner')
        self.logger.setLevel(logging.DEBUG)

        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)

    def info(self, message):
        self.logger.info(message)

    def warning(self, message):
        self.logger.warning(message)

    def error(self, message):
        self.logger.error(message)

    def debug(self, message):
        self.logger.debug(message)

    def vuln(self, message):
        self.logger.warning(f"VULNERABILITY: {message}")

logger = Logger()
