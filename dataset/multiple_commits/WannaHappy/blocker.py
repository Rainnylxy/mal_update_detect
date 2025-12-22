import os
import hashlib
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from colorama import Fore, init
from pyfiglet import figlet_format
import time

USER_HOME = os.path.expanduser("~")

WATCHED_DIRS = [
    os.path.join(USER_HOME, "Downloads"),
    os.path.join(USER_HOME, "Desktop"),
    os.path.join(USER_HOME, "Documents"),
    os.path.join(USER_HOME, "Music"),
    os.path.join(USER_HOME, "Pictures"),
    os.path.join(USER_HOME, "Videos"),
]
# You can also put different directories that you use, it depends on your taste.
file_info_store = {}

def get_file_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def get_process_using_file(path):
    for proc in psutil.process_iter(['pid', 'name', 'open_files']):
        try:
            files = proc.info['open_files']
            if files:
                for file in files:
                    if file.path == path:
                        return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

def initial_scan():
    """Stores hashes and extensions of all files in the watched directories."""
    for directory in WATCHED_DIRS:
        for root, _, files in os.walk(directory):
            for file in files:
                path = os.path.join(root, file)
                file_hash = get_file_hash(path)
                ext = os.path.splitext(file)[1].lower()
                if file_hash:
                    file_info_store[path] = (file_hash, ext)

class MonitorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return

        path = event.src_path
        filename = os.path.basename(path)
        current_ext = os.path.splitext(filename)[1].lower()
        new_hash = get_file_hash(path)

        previous = file_info_store.get(path)

        suspicious = False

        if previous:
            old_hash, old_ext = previous
            if old_hash != new_hash:
                print(f"[!] File content changed: {path}")
                suspicious = True
            elif old_ext != current_ext:
                print(f"[!] File extension changed: {path} ({old_ext} → {current_ext})")
                suspicious = True
        else:

            file_info_store[path] = (new_hash, current_ext)

        if suspicious:
            proc = get_process_using_file(path)
            if proc:
                try:
                    print(f"[!] Suspicious process: {proc.name()} (PID: {proc.pid}) → TERMINATING")
                    proc.terminate()
                except Exception as e:
                    print(f"[!] Process could not be terminated: {e}")


        if new_hash:
            file_info_store[path] = (new_hash, current_ext)

def start_monitoring():
    observer = Observer()
    handler = MonitorHandler()

    for directory in WATCHED_DIRS:
        if os.path.exists(directory):
            print(f"[+] Monitoring: {directory}")
            observer.schedule(handler, directory, recursive=True)
        else:
            print(f"[-] Directory not found: {directory}")

    observer.start()
    try:
        while True:
            time.sleep(0.8)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    print(Fore.GREEN + figlet_format("WannaHappy", font="slant"))
    print("[*] Performing initial scan...")
    initial_scan()
    print("[*] Monitoring started... [Press CTRL+C to exit]")
    start_monitoring()
