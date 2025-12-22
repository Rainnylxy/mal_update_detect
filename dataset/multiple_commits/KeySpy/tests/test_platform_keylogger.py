import unittest
from unittest.mock import patch
from platform.linux_keylogger import LinuxKeylogger
from platform.mac_keylogger import MacKeylogger
from platform.windows_keylogger import WindowsKeylogger

class TestPlatformKeyloggers(unittest.TestCase):
    def setUp(self):
        self.keystroke = "TestKey"

    @patch("platform.linux_keylogger.LinuxKeylogger._process_keystroke")
    def test_linux_keylogger(self, mock_process_keystroke):
        keylogger = LinuxKeylogger()
        keylogger._on_key_press(self.keystroke)
        mock_process_keystroke.assert_called_with(self.keystroke)

    @patch("platform.mac_keylogger.MacKeylogger._process_keystroke")
    def test_mac_keylogger(self, mock_process_keystroke):
        keylogger = MacKeylogger()
        keylogger._on_key_press(self.keystroke)
        mock_process_keystroke.assert_called_with(self.keystroke)

    @patch("platform.windows_keylogger.WindowsKeylogger._process_keystroke")
    def test_windows_keylogger(self, mock_process_keystroke):
        keylogger = WindowsKeylogger()
        keylogger._on_key_press(self.keystroke)
        mock_process_keystroke.assert_called_with(self.keystroke)

if __name__ == "__main__":
    unittest.main()
