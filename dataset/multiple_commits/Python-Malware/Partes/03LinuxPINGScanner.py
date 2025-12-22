import socket as socket
import subprocess

ips = []
ips_on = []
ip_port_on = []


#IP INTERNA
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
ip = s.getsockname()[0].split('.')
s.close()





#RANGO DE IP'S (192.168.X.1-255)
for i in range(1,256):
    ip_full = str(ip[0]+'.'+ip[1]+'.'+ip[2]+'.'+str(i))
    ips.append(ip_full)



	

for ip in ips:
    res = subprocess.call(['ping', '-c', '1', ip])
    #OK CONNECTION
    if res == 0:
        ips_on.append(ip)
    #NO RESPONSE
    elif res == 2:
        continue
    #FAILED CONNECTION
    else:
        continue

print ips_on

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
