#Importar socket (endpoints)
from socket import *

#socket('family', 'type')
#  Family:
#    AF_INET = IPv4
#    AF_INET6 = IPv6
#  Types:
#    SOCK_STREAM = TCP
#    SOCK_DGRAM = UDP

#Enviar datos
envio = socket.send(DATOS A ENVIAR)
#PARA ESPERAR HASTA QUE TODO HAYA SIDO ENVIADO, USAR:
socket.sendall('DATOS A ENVIAR')

#Recibir datos
reci = socket.recv(TAMAÑO DE LO RECIBIDO)
print reci




#Creamos un socket
s = socket(AF_INET,SOCK_STREAM) 

#Iniciamos la conexión
s.connect(('www.python.org',80))

#Enviamos una petición GET al indice de la página
s.send("GET /index.html HTTP/1.0\n\n")

#Recibimos la información (con el tamaño máximo especificado)
data = s.recv(10000)

#Mostramos la información recibida
print(data)

#Cerramos la conexión
s.close()

#RESULTADO:
#HTTP/1.1 500 Domain Not Found
#Server: Varnish
#Retry-After: 0
#content-type: text/html
#Cache-Control: private, no-cache
#connection: keep-alive
#Content-Length: 179
#Accept-Ranges: bytes
#Date: Fri, 31 Mar 2017 09:38:45 GMT
#Via: 1.1 varnish

#Connection: close
#<html>
#<head>
#<title>Fastly error: unknown domain </title>
#</head>
#<body>
#Fastly error: unknown domain: . Please check that this domain has been added to a service.</body></html>


################################################################################################################################

#Cliente basico
#Se conecta al servidor de localhost y envía un mensaje 'Hello'
from socket import *
s = socket(AF_INET,SOCK_STREAM)
s.connect(('127.0.0.1',9000))
#Enviamos algo
s.send('Hello')
#Luego recibe la respuesta
data = s.recv(10000)
print data
s.close()

#RESULTADO:
#Hello 127.0.0.1

################################################################################################################################

#Servidor basico
#Escucha en el puerto 9000 a las conexiones y las acepta
from socket import *
s = socket(AF_INET,SOCK_STREAM)
#Inicia con todas las direcciones (o a la que le indicamos s.bind('127.0.0.1',9000)) en el puerto que indicamos
s.bind(("",9000))
#Escucha 5 conexiones como máximo
s.listen(5)
while True:
	#Esto es una pareja
	#C es el socket object
	#A es la dirección y puerto ("127.0.0.1",60542)
	c,a = s.accept()
	#Luego muestra por pantalla quién se ha conectado
	print 'Received connection from ', a
	#Y le envía una respuesta
	c.send("Hello %s\n" % a[0])
s.close

#RESULTADO:
#Received connection from  ('127.0.0.1', 60242)

################################################################################################################################





