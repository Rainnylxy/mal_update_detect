import hashlib
import colorama
from colorama import Fore
import mimetypes
import os
import requests

colorama.init(autoreset=True)

def query_md5_online(md5_hash):
    try:
        md5_hash_upper = md5_hash.upper()
        url = f"https://www.nictasoft.com/ace/md5/{md5_hash_upper}"
        response = requests.get(url)
        if response.status_code == 200:
            result = response.text
            if "This file is not yet rated" in result:
                print(Fore.GREEN + "This file was not found in the online virus database. It appears safe.")
            else:
                print(Fore.RED + "Warning! This file is flagged as malicious in the online database:")
        else:
            print(Fore.YELLOW + "Online query failed. Check the API connection.")
    except Exception as e:
        print(Fore.RED + f"Error during online hash query: {e}")

def calculate_file_hash(file_path):
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
            return hashlib.md5(file_data).hexdigest(), file_data
    except FileNotFoundError:
        print(Fore.RED + "File not found. Please provide a valid file path.")
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}")
    return None, None

def local_analysis(file_path, file_data):
    try:
        file_name = os.path.basename(file_path)
        file_type, _ = mimetypes.guess_type(file_path)
        print(Fore.CYAN + f"File Name: {file_name}")
        print(Fore.MAGENTA + f"File Type: {file_type if file_type else 'Unknown'}")

        if file_data:
            content_preview = file_data[:100].decode(errors='replace')
            print(Fore.LIGHTBLUE_EX + "File Content Preview:")
            print(Fore.LIGHTWHITE_EX + content_preview)
    except Exception as e:
        print(Fore.RED + f"Error during local file analysis: {e}")

def analyze_file(file_path):
    print(Fore.YELLOW + f"Analyzing file: {file_path}...")
    file_hash, file_data = calculate_file_hash(file_path)

    if file_hash:
        print(Fore.CYAN + f"File Hash: {file_hash}")
        query_md5_online(file_hash)
        local_analysis(file_path, file_data)
    else:
        print(Fore.RED + "File analysis failed.")

def main():
    print(Fore.BLUE + """
WannaHappy VIRUS SCANNER
""")
    while True:
        file_path = input(Fore.YELLOW + "Enter file path (or 'q' to quit): ")
        if file_path.lower() == "q":
            print(Fore.BLUE + "Exiting...")
            break
        analyze_file(file_path)

if __name__ == "__main__":
    main()

