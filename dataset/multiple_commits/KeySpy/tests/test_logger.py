import unittest
from unittest.mock import patch, MagicMock
from core.logger import Keylogger
from core.data_handler import DataHandler

class TestLogger(unittest.TestCase):
    def setUp(self):
        self.keylogger = Keylogger()
    
    @patch("core.logger.logging")
    def test_local_logging(self, mock_logging):
        keystroke = "TestKey"
        self.keylogger._process_keystroke(keystroke)
        mock_logging.getLogger().info.assert_called_with(f"Keystroke: {keystroke}")

    @patch.object(DataHandler, 'encrypt_data', return_value="EncryptedKey")
    def test_encrypted_logging(self, mock_encrypt):
        self.keylogger.encryption_enabled = True
        keystroke = "TestKey"
        self.keylogger._process_keystroke(keystroke)
        mock_encrypt.assert_called_with(keystroke)

    @patch.object(DataHandler, 'remote_log')
    def test_remote_logging(self, mock_remote_log):
        self.keylogger.remote_logging_enabled = True
        keystroke = "TestKey"
        self.keylogger._process_keystroke(keystroke)
        mock_remote_log.assert_called_with(keystroke)

if __name__ == "__main__":
    unittest.main()
