import socket

#Creamos el socket en esa dirección y puerto
s = socket.socket()
s.bind(("localhost", 9999))
s.listen(1)

#Aceptamos la conexión
sc, addr = s.accept()

#Bucle de repetición
while True:
    recibido = sc.recv(1024)
    if recibido == "quit":
        break
    print "Recibido: ", recibido
    sc.send(recibido)

#Si salimos escribimos "adios"
print "adios"

sc.close()
s.close()
