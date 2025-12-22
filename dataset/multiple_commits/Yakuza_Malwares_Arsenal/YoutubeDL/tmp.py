from art import text2art
from termcolor import colored


text = 'Yakuza'
text2 = 'Arsenal'
asciiArt = text2art(text, font='tarty1')
asciiArt2 = text2art(text2, font='poison', decoration='tiny')
asciiArt3 = text2art('Written by Davood Yakuza', font='coptic2')
# asciiArt = text2art(text, font='block', decoration='full')

# print(asciiArt)
# print(asciiArt2)
# print(asciiArt3)

def banner(): # noqa

    def rainbow_text(text):
        colors = ['red', 'yellow', 'green', 'cyan', 'blue', 'magenta']
        rainbow_banner = ""

        for i, char in enumerate(text):
            color = colors[i % len(colors)]
            rainbow_banner += colored(char, color) # noqa

        return rainbow_banner


    bannerText = "Yakuza Youtube \nDownloader"
    asciiArt2 = text2art(text2, font='poison', decoration='tiny')
    asciiArt4 = text2art('Youtube Downloader', font='tarty2')
    asciiBanner = asciiArt + asciiArt2

    coloredBanner = rainbow_text(asciiBanner)
    coloredBanner2 = rainbow_text(asciiArt3)

    print(coloredBanner)
    print(asciiArt4)
    print(coloredBanner2)
banner()