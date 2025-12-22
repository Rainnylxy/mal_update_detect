import platform
import subprocess
import sys

def install_python_packages():
    print("Installing Python packages...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    print("Python packages installed successfully.")

def install_system_packages():
    os_name = platform.system()
    print(f"Detected OS: {os_name}")
    
    if os_name == "Linux":
        subprocess.call(["sudo", "apt", "update"])
        subprocess.call(["sudo", "apt", "install", "-y", "python3-pip", "python3-venv"])
    elif os_name == "Darwin":
        subprocess.call(["brew", "update"])
        subprocess.call(["brew", "install", "python3"])
    elif os_name == "Windows":
        print("Ensure Python and pip are installed from https://www.python.org/downloads/")
    else:
        print("Unsupported operating system.")

if __name__ == "__main__":
    install_system_packages()
    install_python_packages()
