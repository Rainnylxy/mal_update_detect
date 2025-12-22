fragmentos = [] #Vacío

while not done:
	chunk = s.recv(1000) #Indicamos el tamaño de cada bloque
	if not chunk:
		break		#Si no queda ningún bloque ya, se detiene
	fragmentos.append(chunk) #Ha ido añadiendo los bloques a la lista
message = "".join(fragmentos)

