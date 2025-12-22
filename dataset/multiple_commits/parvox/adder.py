A_VERSION = 1.5
from colorama import Fore, Back
import subprocess
import os
from time import sleep
#FUNC (ADD PAYLOAD TO FILE) (STRING) (STRING)
def aptf(pname, fname):
    if not os.path.isfile(f"./payloads/{pname}"):
        print(f"Error: {pname} not found in 'payloads' folder")
        return
    print(f"{Fore.YELLOW}[{Fore.LIGHTRED_EX}\\{Fore.YELLOW}]{Fore.RESET} Adding {pname} to {fname} {Fore.YELLOW} (HAPPY HACKING) {Fore.RESET}")
    ffp = open(f"./payloads/{pname}", "r")
    fftp = open(f"./output/{fname}", "a")
    for i in ffp.readlines():
        fftp.write(i)
        print("[%] Added line.")

def buildm(mname, micon):
    print(f"{Fore.YELLOW}[+]{Fore.RESET} Building malware... ({mname}) with icon ({micon})")
    
    if not os.path.isfile(f"./output/{mname}"):
        print(f"Error: {mname} not found in 'output' folder")
        return
    elif not os.path.isfile(f"./icons/{micon}"):
        print(f"Error: {mname} not found in 'icons' folder")
        return

    sleep(2)
    print(Back.BLACK, Fore.BLACK)
    subprocess.call(f"pyinstaller --onefile ./output/{mname} --icon=./icons/{micon}", shell=True)
    #print(f"pyinstaller --onefile ./output/{mname} --icon=./icons/{micon}")
    print()
    print(f"{Back.RESET}{Fore.GREEN}[+] Finished.{Fore.RESET}")



