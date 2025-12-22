# -*- coding: UTF-8 -*-
#Cliente basico
#Se conecta al servidor de localhost y envía un mensaje 'Hello'
try:
	from socket import *
	s = socket(AF_INET,SOCK_STREAM)
	s.connect(('127.0.0.1',9000))
	#Luego recibe la respuesta
	while True:
		data = s.recv(10000)
	print 'En el servidor se escogió la opción: ' + data
	s.close()
except:
	print 'Error en la conexión'


