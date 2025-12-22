#CLIENT
import socket 

HOST = "127.0.0.1" 
PORT = 9999

def main(): 
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    client_socket.connect((HOST, PORT))
    
    client_message = "Hello world"
    client_socket.send(client_message.encode()) 
    client_socket.close() 

main() 