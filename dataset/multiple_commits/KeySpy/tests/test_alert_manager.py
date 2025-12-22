import unittest
from unittest.mock import patch, MagicMock
from core.alert_manager import AlertManager

class TestAlertManager(unittest.TestCase):
    def setUp(self):
        self.alert_manager = AlertManager()

    @patch("smtplib.SMTP")
    def test_email_alert(self, mock_smtp):
        self.alert_manager.send_email_alert("Test email alert")
        mock_smtp.assert_called_once()
        smtp_instance = mock_smtp.return_value
        smtp_instance.sendmail.assert_called()

    @patch("twilio.rest.Client.messages.create")
    def test_sms_alert(self, mock_sms):
        self.alert_manager.send_sms_alert("Test SMS alert")
        mock_sms.assert_called_once()

if __name__ == "__main__":
    unittest.main()
