# -*- coding: utf-8 -*-
import os
import sys
import platform
import getpass
import socket
import uuid
import urllib
import time

#SISTEMA OPERATIVO
sys_platform = platform.platform()
proces    = platform.processor()
arch = platform.architecture()[0]

#USUARIO EN SESIÓN
user = getpass.getuser()

#RED
hostname    = socket.gethostname()
fqdn        = socket.getfqdn()			#Nombre Domin. asociado
internal_ip = socket.gethostbyname(hostname)
raw_mac     = uuid.getnode()
mac         = ':'.join(('%012X' % raw_mac)[i:i+2] for i in range(0, 12, 2))

#IP EXTERNA
ex_ip_grab = [ 'ipinfo.io/ip', 'icanhazip.com', 'ident.me',
			   'ipecho.net/plain', 'myexternalip.com/raw',
			   'wtfismyip.com/text' ]
external_ip = ''
#PRUEBA TODAS LAS URLS DE LA LISTA
for url in ex_ip_grab:
	try:
		#ABRE LA URL SELECCIONADA Y DEVUELVE LA INFORMACIÓN QUE RECIBE ELIMINANDO EL ESPACIADO EN BLANCO
		external_ip = urllib.urlopen('http://'+url).read().rstrip() #XXX.YYY.ZZZ.KKK
	except IOError:
		pass
	#SI NO HAY ERRORES EN LA IP Y ESTÁ COMPRENDIDA ENTRE 7 Y 15 (INCLUSIVES) DÍGITOS, TERMINA EL BUCLE DE LAS URLS
	if external_ip and (6 < len(external_ip) < 16):
		break

# DATATIME DEL DISPOSITIVO
dt = time.strftime('%a, %d %b %Y %H:%M:%S {}'.format(time.tzname[0]),
	 time.localtime())
	
	

all = {'Plataforma' : sys_platform, 'Procesador' : proces, 'Arquitectura' : arch, 'Usuario' : user, 'Hostname' : hostname, 'MAC' : mac, 'IP Interna' : internal_ip, 'IP Externa' : external_ip, 'Fecha' : dt }
print all.items()

return all
