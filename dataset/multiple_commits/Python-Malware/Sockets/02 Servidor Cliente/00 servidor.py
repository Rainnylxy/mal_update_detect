#Servidor bsico
#Escucha en el puerto 9000 a las conexiones y las acepta
from socket import *
s = socket(AF_INET,SOCK_STREAM)
s.bind(("",9000))
s.listen(5)
while True:
	c,a = s.accept()
	#Luego muestra por pantalla quién se ha conectado
	print 'Received connection from ', a
	#Y le envía una respuesta
	c.send("Hello %s\n" % a[0])
	s.close
