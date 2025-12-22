""" this Module is used to Download video, audio, mp3 and Auto Subtitles from the YouTube
    this submodule is used in the Yakuza Pentest Arsenal project

Author: Davood.Yakuza
---
Develop Start Date: 11/1/2024 => 12 aban 1403
Develop End Date:
"""


from tkinter import Tk
from os import chdir, path, name
from subprocess import run
from tkinter import filedialog
# from pyfiglet import figlet_format
from termcolor import colored
from art import text2art

from miscs.colors import fColors, bColors
from miscs.string_format import stringFormat

from main import main as MainMenu


# TODO:
#   1. Colorize the print and input contents
#   2. fix tool updating, implement using pip 

# Step 1: Define Application Utilities Class and Functions
class Utilities:
    def __init__(self):
        pass

    @staticmethod
    def banner(): # noqa

        def rainbow_text(text):
            colors = ['red', 'yellow', 'green', 'cyan', 'blue', 'magenta']
            rainbow_banner = ""

            for i, char in enumerate(text):
                color = colors[i % len(colors)]
                rainbow_banner += colored(char, color) # noqa

            return rainbow_banner


        # asciiBanner = figlet_format("Yakuza Youtube \nDownloader")

        asciiArt = text2art('Yakuza Youtube', font='tarty1')
        asciiArt2 = text2art('Arsenal', font='poison', decoration='tiny')
        asciiArt3 = text2art('Youtube Downloader', font='bold_script')
        asciiArt4 = text2art('Written by Davood Yakuza', font='coptic2')


        coloredBanner = rainbow_text(asciiArt + asciiArt2)
        coloredBanner2 = rainbow_text(asciiArt4)

        print(coloredBanner)
        print(asciiArt3)
        print(coloredBanner2)


    # Step 1.1: Define the function to give Option from user, also exit and update handle in this function
    @staticmethod
    def option_chooser():
        print(bColors.WHITE + fColors.BLACK + stringFormat.BOLD + "[+*+]-->> Yakuza Youtube Downloader <<--[+*+]"
              + stringFormat.RESET)

        print(fColors.GREEN + """
    [***] Choose an Option To Start Application [***]   
            
            [1]- Available Formats
            [2]- Video Downloader
            [3]- Audio Downloader
            [4]- MP3 Downloader
            [5]- Playlist Downloader
            
            [6]- Subtitle Downloader
            [7]- Live Stream Downloader
        
            [0]- Back to Main Menu
            [88]- Update Tool
            [99]- Exit
            
        """)
        option = int(input(fColors.LIGHT_YELLOW + "[+] Enter Option Number => "))

        if option == 99:
            print("[*] Exiting the application.")
            exit()

        elif option == 0:
            # from main import main as MainMenu
            return MainMenu.launcher()


        elif option == 88:
            Utilities.update_tool()
            return Utilities.option_chooser()

        if option not in range(-1, 7):
            print(fColors.LIGHT_RED + "[-] Invalid Option Number. Please choose a valid option.")
            return Utilities.option_chooser()

        return option

    # Step 1.2: Define the function to ask user for save path
    # noinspection PyShadowingNames
    @staticmethod
    def ask_save_path(directory=False):
        root = Tk()
        root.withdraw()

        # if the directory Flag is True, then ask for directory, else ask for the file path
        if directory:
            savePath = filedialog.askdirectory()
            return savePath

        savePath = filedialog.asksaveasfilename(defaultextension=".mp4",
                                                filetypes=[("MP4 files", "*.mp4"), ("All files", "*.*")])
        return savePath

    @staticmethod
    def get_video_specification(audio=False):
        # Example usage
        url = input(fColors.LIGHT_YELLOW + "[+] Enter the video URL: ")

        # if the video option chooses and audio flag set False, show Video downloading Prompt
        if not audio:
            subtitleLang = input(fColors.LIGHT_YELLOW + "[+] Enter the subtitle language (e.g., fa): ") or "fa"
            resolution = input(fColors.LIGHT_YELLOW +"[+] Enter the Video resolution (e.g., 720): ") or "720"

        # if the audio option chooses and audio flag set True, show audio downloading Prompt
        else:
            resolution = input(fColors.LIGHT_YELLOW + "[+] Enter the Audio resolution (e.g., 720): ") or "720"

        savePath = Utilities.ask_save_path(directory=True) or path.abspath(".")
        if not savePath:
            print(fColors.LIGHT_RED + "[-] No save path selected. Exiting.")
            exit()

        if audio:
            return url, resolution, savePath

        return url, resolution, subtitleLang, savePath # noqa

    @staticmethod
    def get_mp3_specification():
        # Example usage
        url = input(fColors.LIGHT_YELLOW + "[+] Enter the video URL: ")
        savePath = Utilities.ask_save_path(directory=True) or path.abspath(".")

        if not savePath:
            print(fColors.LIGHT_RED + "[-] No save path selected. Exiting.")
            exit()

        return url, savePath

    @staticmethod
    def open_folder(path):
        chdir(path)
        run(['explorer', '.'])

    @staticmethod
    def update_tool():

        # use this command as default if os not windows or linux(other os)
        command = ["pip", "install", "--upgrade", "yt-dlp"]

        # if the operating system is windows
        if name == "nt":
            command = ["python", "-m", "pip", "install", "--upgrade", "yt-dlp"]

        # if the operating system is linux
        elif name == "posix":
            command = ["pip", "install", "--upgrade", "yt-dlp"]

        # If you use the non-python version of yt-dlp, use the following command.
        # Command = ["yt-dlp", "-U"]

        run(command)
        print(fColors.GREEN + "\n[+] Tool updated successfully.")


# format_string = "bestaudio"
# Step 2: Define Downloading Class and Functions

# noinspection PyPep8Naming
class Downloader:
    def __init__(self):
        pass

    @staticmethod
    def list_formats(url):
        command = [
            "yt-dlp",
            "-F",       # "--list-formats"
            "--no-playlist",
            url
        ]

        run(command)

    # Step 2.1: Define Function to Download Video and Audio
    @staticmethod
    def video_downloader(resolution, url, subtitle_lang, save_path, isPlaylistDl="no", audio_download=False):  # noqa
        # Initialize the format string compatible based on the audio_download flag
        if not audio_download:
            formatString = f"bestvideo[height={resolution}]+bestaudio/best[height={resolution}]"
        else:
            formatString = "bestaudio"

        # Check if the URL is a Playlist URL
        if "list=" in url.lower() or "index=" in url.lower():
            print(fColors.LIGHT_RED + "[*] This is URL of a Playlist , Please choose the appropriate option.")
            isPlaylistDl = input(fColors.LIGHT_YELLOW + "[?] Do you want to download the full playlist? (yes/no): ").lower()

        # Base command
        command = [
            "yt-dlp",
            "-f", formatString,
            "--write-auto-sub",
            "--sub-lang", subtitle_lang,
            "--output", f"{save_path.replace('/', '\\')}\\%(title)s.%(ext)s",
            url,
            "--no-playlist"
        ]

        if isPlaylistDl.startswith("y"):
            command.remove("--no-playlist")
            # command.append("--yes-playlist") # by default yt-dlp download full playlist

        run(command)

    # Step 2.2: Define Function to Download Audio
    @staticmethod
    def mp3_downloader(url, save_path, isPlaylistDl="no"):

        # Check if the URL is a Playlist URL
        if "list=" in url.lower() or "index=" in url.lower():
            print(fColors.LIGHT_RED + "[*] This is URL of a Playlist , Please choose the appropriate option.")
            isPlaylistDl = input(fColors.LIGHT_YELLOW + "[?] Do you want to download the full playlist? (yes/no): ").lower()

        # Base command
        command = [
            "yt-dlp",
            "--extract-audio",
            "--audio-format", "mp3",
            "--output", f"{save_path.replace('/', '\\')}\\%(title)s.%(ext)s",
            url,
            "--no-playlist"
        ]

        if isPlaylistDl.startswith("y"):
            command.remove("--no-playlist")
            # command.append("--yes-playlist") # by default yt-dlp download full playlist

        run(command)

    @staticmethod
    def playlist_downloader(url, save_path, resolution="720", subtitle_lang="fa"):
        wholePlaylist = input(fColors.LIGHT_YELLOW + "[+] Do you want to download the full playlist? (yes/no): ").lower()
        formatString = f"bestvideo[height={resolution}]+bestaudio/best[height={resolution}]"


        if wholePlaylist.startswith("y"):
            command = [
                "yt-dlp",
                "-f", formatString,
                "--write-auto-sub",
                "--sub-lang", subtitle_lang,
                "--output", f"{save_path.replace('/', '\\')}\\%(title)s.%(ext)s",
                url
            ]

        else:
            startRange = input(fColors.LIGHT_YELLOW + "[?] Enter the Start Item: ")
            endRange = input(fColors.LIGHT_YELLOW + "[?] Enter the End Item: ")

            command = [
                "yt-dlp",
                "-f", formatString,
                "--write-auto-sub",
                "--sub-lang", subtitle_lang,
                '--playlist-start', startRange,
                '--playlist-end', endRange,
                "--output", f"{save_path.replace('/', '\\')}\\%(title)s.%(ext)s",
                url
            ]

        run(command)

def launcher():
    Utilities.banner()
    while True:
        option = Utilities.option_chooser()

        if option == 1:
            print(fColors.GREEN + stringFormat.BOLD + "[***] List of Available Formats [***]\n" + stringFormat.RESET)
            url = input(fColors.LIGHT_YELLOW + "[?] Enter the video URL: ")
            Downloader.list_formats(url)
            continue

        # if option == 1 mean Video Downloader choose by user
        if option == 2:
            print(fColors.GREEN + stringFormat.BOLD + "[***] Video Downloader [***]\n" + stringFormat.RESET)

            url, resolution, subtitleLang, savePath = Utilities.get_video_specification()
            Downloader.video_downloader(resolution, url, subtitleLang, savePath)

            # Open downloaded location in the file explorer
            Utilities.open_folder(savePath)
            continue

        # if option == 2 mean Audio Downloader choose by user
        elif option == 3:
            print(fColors.GREEN +stringFormat.BOLD +  "[***] Audio Downloader [***]\n" + stringFormat.RESET)

            url, resolution, savePath = Utilities.get_video_specification(audio=True)
            Downloader.video_downloader(resolution, url, "en", savePath, audio_download=True)

            # Open downloaded location in the file explorer
            Utilities.open_folder(savePath)
            continue

        # if option == 3 mean MP3 Downloader choose by user
        elif option == 4:
            print(fColors.GREEN + stringFormat.BOLD + "[***] MP3 Downloader [***]\n" + stringFormat.RESET)

            url, savePath = Utilities.get_mp3_specification()
            Downloader.mp3_downloader(url, savePath)

            # Open downloaded location in the file explorer
            Utilities.open_folder(savePath)
            continue

        # if option == 3 mean MP3 Downloader choose by user
        elif option == 5:
            print(fColors.GREEN + stringFormat.BOLD + "[***] Playlist Downloader [***]\n" + stringFormat.RESET)

            url, resolution, subtitleLang, savePath = Utilities.get_video_specification()
            Downloader.playlist_downloader(url, savePath, resolution, subtitleLang)

            # Open downloaded location in the file explorer
            Utilities.open_folder(savePath)
            continue



# Final Step: Main Execution
if __name__ == "__main__":
    launcher()
