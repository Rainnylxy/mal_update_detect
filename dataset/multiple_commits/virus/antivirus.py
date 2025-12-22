import os
import shutil
import pyAesCrypt

# encryption/decryption buffer size - 64K
bufferSize = 64 * 1024

def unlock_dir(directory):
    # check if the directory has been locked
    if not os.path.exists(f"{directory}.zip.aes"):
        return "The directory has not been locked"

    password = "123"

    # decrypt the file
    try:
        pyAesCrypt.decryptFile(f"{directory}.zip.aes", f"{directory}.zip", password, bufferSize)
    except ValueError:
        return "The password is incorrect"
    
    # extract the zip file
    shutil.unpack_archive(f"{directory}.zip", directory, 'zip')
    
    # delete the encrypted and zip file
    os.remove(f"{directory}.zip.aes")
    os.remove(f"{directory}.zip")


# unlock the directory
dirs_to_unlock = ["Data"]

for dir in dirs_to_unlock:
    root_dir = os.path.expanduser('~')
    file_to_unlock = os.path.join(root_dir, dir)
    if (file_to_unlock):
      unlock_dir(file_to_unlock)
