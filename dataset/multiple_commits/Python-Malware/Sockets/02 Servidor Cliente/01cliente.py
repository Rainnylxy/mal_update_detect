import socket
#Creamos el socket y elegimos puerto y dirección
s = socket.socket()
s.connect(("localhost", 9999))

#Bucle de repetición
while True:
    mensaje = raw_input("> ")
    s.send(mensaje)
    if mensaje == "quit":
        break

#Si la palabra insertada es quit, sale del programa mostrando 'adios' print "adios"
s.close()
