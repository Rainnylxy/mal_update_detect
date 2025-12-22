#!/usr/bin/python3

import secrets

from tkinter import *


# Check if key matches

def checkToken():
   if usr.get() == token:
      root.destroy()

   else:
      nomatch = Label(text='Incorrect token.', bg='black', fg='white', font=40)
      nomatch.place(relx=.5, rely=.75, anchor=CENTER)
      

# Disable window attributes

def disable_event():
   pass

if __name__ == "__main__":

    # Generate token

    token = secrets.token_hex(16)
    print(token)


    # Create locker window

    root = Tk()
    root.title('VIGIL RANSOM LOCKER')
    root.attributes('-fullscreen', True)
    root.protocol("WM_DELETE_WINDOW", disable_event)
    root.resizable(width=FALSE, height=FALSE)
    root.configure(bg='black')

    canvas = Canvas(root, width=635, height=200, bg='black', bd=0)
    canvas.config(highlightbackground='black')
    vigil = PhotoImage(file='vigil.png')
    canvas.create_image(20,20, anchor=NW, image=vigil)
    canvas.place(relx=.5, rely=.3, anchor=CENTER)

    prompt = Label(text='You have been locked out. \nFollow instructions to receive token.\n', bg='black', fg='white', font=40)
    prompt.place(relx=.5, rely=.5, anchor=CENTER)

    distoken = Text(root, height=1, bd=0, bg='black', fg='red', font='80')
    distoken.config(highlightbackground='black')
    distoken.tag_configure("center", justify='center')
    distoken.insert(1.0, token)
    distoken.tag_add("center", "1.0", "end")
    distoken.place(relx=.5, rely=.55, anchor=CENTER)

    label = Label(text='Enter token to enter: ', bg='black', fg='white', font=40)
    label.place(relx=.5, rely=.6, anchor=CENTER)

    usr = Entry(root, font=('Arial Black', 12))
    usr.place(relx=.5, rely=.65, anchor=CENTER)

    enter = Button(root, text='Submit', font=40, command=checkToken)
    enter.place(relx=.5, rely=.7, anchor=CENTER)

    root.mainloop()




