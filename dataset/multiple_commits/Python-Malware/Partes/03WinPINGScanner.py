import subprocess
import socket

#IP INTERNA
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
ip = s.getsockname()[0].split('.')
s.close()


#RANGO DE IP'S (192.168.X.1-255)
ips = []          #Rango de ip's
ips_on = []       #IP's de dispositivos encendidos
ip_port_on = []   #Puertos abiertos de IP's de dispositivos encendidos

for i in range(1,256):
    ip_full = str(ip[0]+'.'+ip[1]+'.'+ip[2]+'.'+str(i))
    ips.append(ip_full)

for ip in ips:
    print 'Scanning ',ip
    output = subprocess.Popen(["ping", "-n ", "1", ip],stdout = subprocess.PIPE).communicate()[0]
    print output
    if ('inaccesible' in output):
        print("Offline")
    else:
        ips_on.append(ip)

#print ips_on

for ip_on in ips_on:
    for port in range(1,1024):
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((ip_on,port))
            print 'IP ',ip_on,'Puerto ',port, ' abierto'
            ip_port_on.append(ip_on+'_'+port)
        except:
            #print 'Puerto ',port, ' cerrado'
            pass
        finally:
		    s.close()
print ip_port_on
