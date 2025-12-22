import unittest
from unittest.mock import patch
from core.persistence import PersistenceManager

class TestPersistenceManager(unittest.TestCase):
    def setUp(self):
        self.persistence = PersistenceManager()

    @patch("core.persistence.CronTab.write")
    def test_unix_persistence(self, mock_cron_write):
        with patch("platform.system", return_value="Linux"):
            self.persistence.setup_persistence()
            mock_cron_write.assert_called_once()

    @patch("os.system")
    def test_windows_persistence(self, mock_os_system):
        with patch("platform.system", return_value="Windows"):
            self.persistence.setup_persistence()
            mock_os_system.assert_called_once_with("powershell.exe ...")

if __name__ == "__main__":
    unittest.main()
