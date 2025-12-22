import random


def play_guess_number():
    guess = None
    number_to_guess = random.randint(1, 100)
    while True:
        command: str = input("Guess a number between 1 and 100 (type 'q' to quit): ")
        if command == 'q': return

        try:
            guess: int = int(command)
        except:
            print(f"    '{command}' is not a valid number")
        
        if 1 >= guess or guess >= 100:
            print(f"    '{guess}' is not a valid number")

        if guess == number_to_guess:
            print("\n    Congrats!! You guessed the number correctly ^_^\n")
            number_to_guess = random.randint(1, 100)
        elif guess > number_to_guess:
            print("    You guessed above the number, try a lower guess ^^")
        elif guess < number_to_guess:
            print("    You guessed below the number, try a higher guess ^^")


play_guess_number()

