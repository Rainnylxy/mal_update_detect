import os
from pathlib import Path
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from colorama import Fore, init
from pyfiglet import figlet_format
from concurrent.futures import ThreadPoolExecutor, as_completed

init(autoreset=True)
# RANSOM KEYS HERE BRO
OFFLINE_KEYS = {
    '.djvu':  '6se9RaIxXF9m70zWmx7nL3bVRp691w4SNY8UCir0',
    '.rumba': 'D02NfEP94dKUO3faH1jwqqo5f9uqRw2Etn2lP3VBb',
    '.promos': '6se9RaIxXF9m70zWmx7nL3bVRp691w4SNY8UCir0',
    '.promoz': 'cZs3TaUYZzXCH1vdE44HNr1gnD2LtTIiSFFYv5t1',
    '.kroput': 'upOacGl1yOz9XbrhjX9UR2M0j8i03YwVB0pXr1t1',
    '.charck': 'neFMH56G5TY6gLqHS6TpWwfIPJF1mKg4FvpeNPt1',
    '.verasto': 'fCuKTg0kzQEXr1ewwlkMM3sl8ZzT1uEg7811p2t1',
    '.moresa': 'PBADSc0wL8KOzd5eGIaVThjIPeGxRqrsQgvU3qt1',
    '.pulsar1': 'AlMcLobh5J6wVB2Iy10guKr1kpSuFBWfXIsI6Et1',
    '.drume': 'dLoJuwk26P2wogGWZREN7JEyvljcvICqcYfwIft1',
    '.crypt': '14a0c55d85066d0e4f6fbb8ec8e45d18',
    '.ecc': '0c2214b64f954a2f8e7e4d7a4b9a5f67',
    '.xtbl': '9f8e7d6c5b4a39281726354433221100',
    '.grovas': 'sC0oYeg1wSkjbjkEwQcxTXzA0EOp8Tnc35seYQt1',
    '.roland': 'R11Dxz37SHHVuv5otlFtzJiXUIPwPzmP6gV8gmv9',
    '.gusau': '68O9eTFDNbn8z2O956vweaL1v2GY5gvWBYMKcmt1',
    '.shadow': '6se9RaIxXF9m70zWmx7nL3bVRp691w4SNY8UCir0',
    '.mtogas':'ILhWAvjUyWzsKyxDL0dKq3Su6QUUpndwXWfa2Nt1',
    '.pedro':'98sPqhSP6fu4VGWnM1G9A075ZFxi5MMVRr2Limt1',
    '.locky': 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0',
    '.cerber': 'U1V2W3X4Y5Z6A7B8C9D0E1F2G3H4I5J6K7L8M9N0',
    '.cryptolocker': 'P1Q2R3S4T5U6V7W8X9Y0Z1A2B3C4D5E6F7G8H9I0',
    '.wannacry': 'J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0',
    '.petya': 'D1E2F3G4H5I6J7K8L9M0N1O2P3Q4R5S6T7U8V9W0',
    '.badrabbit': 'Y1Z2A3B4C5D6E7F8G9H0I1J2K3L4M5N6O7P8Q9R0',
    '.dharma': 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0',
    '.conti': 'Z1Y2X3W4V5U6T7S8R9Q0P1O2N3M4L5K6J7I8H9G0',
    '.nephilim': 'F1G2H3I4J5K6L7M8N9O0P1Q2R3R4S5T6U7V8W9X0',
    '.avaddon': 'B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0',
    '.makop': 'T1U2V3W4X5Y6Z7A8B9C0D1E2F3G4H5I6J7K8L9M0',
    '.egregor': 'L1M2N3O4P5Q6R7R8S9T0U1V2W3X4Y5Z6A7B8C9D0',
    '.turkstatik': 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0',
    '.wannacryfake': 'Z1Y2X3W4V5U6T7S8R9Q0P1O2N3M4L5K6J7I8H9G0',
    '.xorist': 'F1G2H3I4J5K6L7M8N9O0P1Q2R3R4S5T6U7V8W9X0',
    '.szflocker': 'B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0',
    '.cryptinfinite': 'T1U2V3W4X5Y6Z7A8B9C0D1E2F3G4H5I6J7K8L9M0',
    '.troldesh': 'N1O2P3Q4R5S6S7T8U9V0W1X2Y3Y4Z5A6B7C8D9E0',
    '.keyranger': 'L1M2N3O4P5Q6R7R8S9T0U1V2W3X4Y5Z6A7B8C9D0',
    '.blackkingdom': '7f6e4a829b0c3d5a6f7e9b2c4d1f3a8b',
    '.carl': '6a2d4f819e1c3b5f8a7d9c0e4b2f1d3c',  
    '.shade': '8b9c0d7a1e2f3b4c5d6e7f809a1b2c3d',      
    '.crylock': '4145535f43425f46495845445f4b4559',  
    '.crypted000007': 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
}



def get_key_bytes(key_b64):
    key = b64decode(key_b64)
    if len(key) < 32:
        key += b'\x00' * (32 - len(key))
    return key

def decrypt_file_aes_cbc(file_path, key_b64):
    key = get_key_bytes(key_b64)
    iv = key[:16]

    try:
        with open(file_path, 'rb') as f:
            ciphertext = f.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        decrypted_path = file_path.with_suffix('')  # Remove the extension
        with open(decrypted_path, 'wb') as f:
            f.write(plaintext)

        print(Fore.GREEN + f"[✓] Decrypted: {file_path.name} → {decrypted_path.name}")
        return True

    except Exception as e:
        print(Fore.RED + f"[✗] Decrypt error {file_path.name}: {e}")
        return False



def process_file(file_path):
    ext = file_path.suffix.lower()
    key_b64 = OFFLINE_KEYS.get(ext)

    if key_b64:
        print(Fore.CYAN + f"[→] Detected variant: {ext} | Key start: {key_b64[:6]}...")
        success = decrypt_file_aes_cbc(file_path, key_b64)
        if not success:
            print(Fore.LIGHTBLACK_EX + f"[-] AES-CBC decryption failed: {file_path.name}")
    else:
        print(Fore.YELLOW + f"[?] No key: {file_path.name}")


def print_banner():
    print(Fore.GREEN + figlet_format("WannaHappy", font="slant"))
    print(Fore.CYAN + "Offline Ransomware Decryptor")
    print(Fore.CYAN + "Developer: @rootzombies")
    print(Fore.RESET)

def main():
    print_banner()
    directory = input(Fore.YELLOW + "[📁] Target folder: ").strip('"')

    p = Path(directory)
    if not p.is_dir():
        print(Fore.RED + "Invalid folder path!")
        return

    files_to_process = list(p.rglob('*'))
    files_to_process = [f for f in files_to_process if f.is_file()]

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(process_file, f) for f in files_to_process]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(Fore.RED + f"[✗] An error occurred: {e}")

if __name__ == "__main__":
    os.system("cls")
    os.system("clear")
    main()
