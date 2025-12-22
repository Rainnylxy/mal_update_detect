import os
import sys
import time
import glob
import shutil
import socket
import subprocess
import threading
import ctypes
import requests
import base64
import winreg as reg
from colorama import Fore, init, Back
import winshell
import win32com.client
import win32api, win32con
from parvox_funcs import *

os_comp()
init()
cls()
logo_com()
print(f"""

Welcome to Parvox terminal, type "help" to get program commands.

""")

def comandeget():
    try:
        print()
        commande = input(f"{Fore.RED}[{Fore.YELLOW}%{Fore.RED}]{Fore.RESET} {Fore.RED}[{Fore.YELLOW}Parvox Terminal{Fore.RED}] > {Fore.RESET}")
        if commande == "help":
            print("""
    - aptf <payload filename> <malware filename> (Add payload to malware.)
    - build <malware name> [icon name]           (Converts a malware to .exe)
    - payloads                                   (Show payloads.)
    - malwares                                   (Show malwares in 'output' folder.)
    
            """)
        elif len(commande.split(" ")) > 1:
            newcommande = commande.split(" ")
            if newcommande[0] == "aptf":
                aptf(newcommande[1],newcommande[2])
            elif newcommande[0] == "build":
                if len(newcommande) > 2:
                    buildm(newcommande[1],newcommande[2])
                else:
                    buildm(newcommande[1],"default.ico")
        elif commande == "payloads":
            pays = glob.glob("./payloads/*")
            for i in pays:
                i2 = i.split("./payloads\\")[1]
                if i2[-3:] != ".py":
                    continue
                print(f"{Fore.YELLOW}-{Fore.RESET} {i2}")
        elif commande == "malwares":
            mals = glob.glob("./output/*")
            if len(mals) == 0:
                return
            for i in mals:
                i2 = i.split("./output\\")[1]
                if i2[-3:] != ".py":
                    continue
                print(f"{Fore.YELLOW}-{Fore.RESET} {i2}")
        elif commande == "exit":
            exit()
        else:
            os.system(commande)
    except:
        cls()
        print(f"{Fore.RED}Exception: {Fore.RESET}Needs to exit!")
        print(f"{Fore.RED}Error code: {Fore.RESET}{sys.exc_info()[0]}")
        exit()

while True:
    comandeget()