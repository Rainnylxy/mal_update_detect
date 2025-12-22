import unittest
from unittest.mock import patch, MagicMock
from core.data_handler import DataHandler

class TestDataHandler(unittest.TestCase):
    def setUp(self):
        self.data_handler = DataHandler()
        self.data_handler.enable_encryption()

    def test_encryption_decryption(self):
        original_data = "TestKey"
        encrypted_data = self.data_handler.encrypt_data(original_data)
        decrypted_data = self.data_handler.decrypt_data(encrypted_data)
        self.assertEqual(decrypted_data, original_data)

    @patch("requests.post")
    def test_remote_logging(self, mock_post):
        log_data = "Test remote log"
        self.data_handler.remote_log(log_data)
        mock_post.assert_called_once()

if __name__ == "__main__":
    unittest.main()
