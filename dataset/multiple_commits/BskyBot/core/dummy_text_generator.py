import random

from core.text_generator import TextGenerator

class DummyTextGenerator(TextGenerator):
    """
    Generates random dummy text from a predefined list.
    """
    def generate(self) -> str:
        """
        Select a random dummy text from the predefined list.

        Returns:
        str: A randomly selected dummy text.
        """
        return random.choice(DummyTextGenerator._dummy_texts)
    
    _dummy_texts = [
        "This fluffy kitty loves napping in the sun!",
        "Cuddle time with this adorable furball!",
        "A purrfect companion for your lazy afternoons!",
        "Whisker kisses and warm cuddles await you!",
        "Meow! Just look at this majestic feline!",
        "Who can resist this playful little kitten?",
        "Snuggle up with this adorable cat today!",
        "Paws and whiskers galore! Such a cutie!",
        "Chasing lasers is this kitty’s favorite game!",
        "Paws-itively adorable and ready to cuddle!",
        "Can you handle this much feline cuteness?",
        "This kitty’s eyes will melt your heart!",
        "Furry, playful, and oh-so-lovable!",
        "A bundle of joy with a tail to match!",
        "Soft paws, sweet purrs, and endless love!",
        "Check out this graceful feline in action!",
        "This cat knows how to strike a pose!",
        "Purrs and cuddles are this kitty’s specialty!",
        "A little fluffball full of curiosity and love!",
        "Life is better with a purring kitty by your side!",
        "Meet the queen of all cat naps!",
        "This kitten’s mischief is cuteness overload!",
        "Whiskers, paws, and a heart full of love!",
        "Ready for an endless supply of purrfection?",
        "From playful leaps to cozy naps, this cat is perfect!",
        "A photogenic kitty with a knack for adventure!",
        "Purrfect moments captured in this photo!",
        "This feline is the epitome of grace and charm!",
        "Prepare for a cuteness overload with this kitty!",
        "Nothing beats a sunny nap for this cat!",
        "This kitty’s purrs are music to the ears!",
        "Just a kitty bringing joy one paw at a time!",
        "Curiosity and cuteness combined in one feline!",
        "Adorable whiskers and a mischievous grin!",
        "Every day is better with this furry companion!",
        "This cat’s purrs will melt your stress away!",
        "A feline friend to brighten your every day!",
        "Whisker-filled wonder and paw-sitive vibes!",
        "From pouncing to purring, this cat has it all!",
        "Cat naps and cuddles make life purrfect!",
        "Tail wags and soft purrs are this cat’s charm!",
        "Meet the furriest friend you’ll ever love!",
        "This kitty’s gaze is simply mesmerizing!",
        "Feline fun and endless affection in one package!",
        "Cuteness wrapped in fur and whiskers!",
        "Paws up for the cutest kitty you’ve ever seen!",
        "Heart-melting purrs and a playful spirit!",
        "This kitten knows how to steal the spotlight!",
        "A cat so cute, it’s practically irresistible!",
        "Sleek, elegant, and full of feline charm!",
        "Purring softly while dreaming of adventures!",
        "This little furball will brighten your day!",
        "A kitty full of personality and playful energy!",
        "Adventures and snuggles await with this kitty!",
        "This feline’s purr is the ultimate comfort!",
        "Bright eyes, soft fur, and a loving heart!",
        "Paws-itively adorable and ready for fun!",
        "Fluffy, cuddly, and totally lovable!",
        "This cat is the definition of feline elegance!",
        "Ready to charm you with purrs and whiskers!",
        "Paws and whiskers, ready to explore the world!",
        "This kitty’s antics will leave you smiling!",
        "Cuteness overload with this furry friend!",
        "A little cat with a lot of love to give!",
        "This playful kitten is full of surprises!",
        "From soft purrs to playful leaps, this cat is a gem!",
        "This kitty’s curiosity is as cute as it gets!",
        "Meet the fluffiest friend you’ll ever have!",
        "Soft fur, bright eyes, and a big personality!",
        "This adorable kitty is ready for its close-up!",
        "Purrs and paws make this cat unforgettable!",
        "Who can resist such a cute feline face?",
        "This kitty knows how to strike a pose!",
        "Graceful, playful, and full of love!",
        "A purrfect photo of a purrfect kitty!",
        "Adorable whiskers and a playful heart!",
        "This cat is the king of cozy cat naps!",
        "Soft fur and sweet purrs await you!",
        "This kitty’s gaze will melt your heart!",
        "Cuddle up with this sweet little furball!",
        "This playful cat is ready for its next adventure!",
        "Purring softly and melting hearts everywhere!",
        "This cat’s charm is simply irresistible!",
        "Soft whiskers and a warm heart make this cat special!",
        "Paws and purrs for the ultimate cat lover!",
        "This kitty is the embodiment of feline grace!",
        "A little cat with a big personality!",
        "This feline friend will brighten your day!",
        "From playful pounces to cozy naps, this cat has it all!",
        "Adorable, lovable, and oh-so-purrfect!",
        "A furry friend to bring you endless joy!",
        "This kitty is ready to steal your heart!"
    ]

    
