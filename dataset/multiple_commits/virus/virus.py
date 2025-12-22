import os
import shutil
import pyAesCrypt
from getpass import getpass

# encryption/decryption buffer size - 64K
bufferSize = 64 * 1024

def delete_dir_contents(directory):
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f'Failed to delete {file_path}. Reason: {e}')

def lock_dir(directory):
    # compress the directory
    shutil.make_archive(directory, 'zip', directory)
    password = "123"
    
    # encrypt the zip file
    pyAesCrypt.encryptFile(f"{directory}.zip", f"{directory}.zip.aes", password, bufferSize)
    
    # delete the original directory
    delete_dir_contents(directory)
    os.remove(f"{directory}.zip")

# lock the directory
dirs_to_lock = ["Data"]

for dir in dirs_to_lock:
    root_dir = os.path.expanduser('~')
    file_to_lock = os.path.join(root_dir, dir)
    if (os.path.exists(file_to_lock)):
      lock_dir(file_to_lock)