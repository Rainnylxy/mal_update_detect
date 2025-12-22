import smtplib
from email.mime.text import MIMEText
from twilio.rest import Client
from config.loader import ConfigLoader

class AlertManager:
    def __init__(self):
        config = ConfigLoader.load_config()
        self.alert_email = config["alert"]["email"]
        self.sms_number = config["alert"]["sms"]

        # Initialize SMS client
        self.twilio_client = Client("account_sid", "auth_token")

    def send_email_alert(self, message):
        msg = MIMEText(message)
        msg["Subject"] = "Keylogger Alert"
        msg["From"] = "keylogger@example.com"
        msg["To"] = self.alert_email

        with smtplib.SMTP("smtp.example.com", 587) as server:
            server.starttls()
            server.login("user@example.com", "password")
            server.sendmail("keylogger@example.com", self.alert_email, msg.as_string())
        print("Email alert sent.")

    def send_sms_alert(self, message):
        try:
            message = self.twilio_client.messages.create(
                body=message,
                from_="+1234567890",
                to=self.sms_number
            )
            print("SMS alert sent.")
        except Exception as e:
            print(f"Failed to send SMS: {e}")
