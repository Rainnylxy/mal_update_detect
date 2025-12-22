#Cliente basico
#Se conecta al servidor de localhost y envía un mensaje 'Hello'
from socket import *
s = socket(AF_INET,SOCK_STREAM)
s.connect(('127.0.0.1',9000))
s.send('Hello')
#Luego recibe la respuesta
data = s.recv(10000)
print data
s.close()
