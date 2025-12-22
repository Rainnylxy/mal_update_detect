from colorama import Fore, init
from pyfiglet import figlet_format
import os
os.system("clear")
os.system("cls")
init(autoreset=True)
print(Fore.GREEN + figlet_format("WannaHappy", font="slant"))
print(Fore.CYAN + "WannaHappy: Ransomware Blocker and Decryptor")
print(Fore.RESET)
print("""
      [1]:  Ransomware RunTime Blocker
      [2]:  Ransomware Encrypted File Decryptor
      [3]:  Scan a Suspicious File  """)
choice = int(input(">> "))
if choice == 1:
    print("Thx to those who use this tool")
    print("\n")
    os.system("python blocker.py")
elif choice == 2:
    print("Thx to those who use this tool")
    print("\n")
    os.system("python decryptor.py")
elif choice == 3:
    print("Thx to those who use this tool")
    print("\n")
    os.system("python scan.py")
