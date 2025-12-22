#!/usr/bin/python
# -*- coding: UTF-8 -*-

#########
#PYCRYPT#
#########





#CIFRADORES (AES ARC2 Blowfish CAST DES DES3 IDEA RC5)
"""Importación del módulo:      from Crypto.Cipher import [Tipo_Cifrador]"""
"""Creación del cifrador:       New ([clave], [modo], [Vector IV])"""
"""Modos:               MODE_ECB, MODE_CBC, MODE_CFB, MODE_PGP, MODE_OFB, MODE_CTR, MODE_OPENPGP."""
#Sólo la clave es obligatorio
#Menos si se utiliza MODE_CBC o MODE_CFB, que hay que utilizar el IV (Valor inicial del cifrador)

"""Encriptar:           encrypt('texto claro')"""
"""Desencriptar:        decrypt('texto encriptado')"""







#HASH (MD2 MD4 MD5 RIPEMD SHA1 SHA256)
"""Importación del módulo:      from Crypto.Hash import [Tipo Hash]"""
"""Creación del hash:           M = MD5.new() """
"""Indicamos el texto:          M.update('Hola mundo')"""
"""Generar hash:                print M.digest() """







#EJEMPLO
from Crypto.Cipher import DES

#Debe haber 8 caracteres siempre en total! (o un múltiplo)
usuario = 'jorge   '
password = 'jorge   '

cipher = DES.new('12345678')

c_usuario = cipher.encrypt(usuario)
c_password = cipher.encrypt(password)

print c_usuario
print c_password
