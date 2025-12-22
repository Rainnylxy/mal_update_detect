import unittest
import os
from config.loader import ConfigLoader

class TestConfigLoader(unittest.TestCase):
    def setUp(self):
        os.environ["APP_ENV"] = "test"
        os.environ["ENCRYPTION_KEY"] = "test_encryption_key"
        os.environ["REMOTE_AUTH_TOKEN"] = "test_auth_token"

    def test_config_loader(self):
        config = ConfigLoader.load_config()
        self.assertEqual(config["environment"], "test")
        self.assertEqual(config["encryption"]["key"], "test_encryption_key")

    def test_env_variables(self):
        app_env = os.getenv("APP_ENV")
        encryption_key = os.getenv("ENCRYPTION_KEY")
        self.assertEqual(app_env, "test")
        self.assertEqual(encryption_key, "test_encryption_key")

if __name__ == "__main__":
    unittest.main()
