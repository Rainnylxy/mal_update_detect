import subprocess
import tkinter as tk
from tkinter import filedialog




def option_chooser():
    print(""" Choose an Option's To Start Application: 
        [1]- Video Downloader
        [2]- Audio Downloader
        [3]- Subtitle Downloader
        [4]- Live Stream Downloader
        
    """)



def download_video(resolution, url, subtitle_lang, download_type, save_path, isPlaylistDl = False): # noqa
    # Determine the format string based on the download type (video or audio)
    if download_type == "video":
        format_string = f"bestvideo[height={resolution}]+bestaudio/best[height={resolution}]"
    elif download_type == "audio":
        format_string = "bestaudio"
    else:
        raise ValueError("Invalid download type. Choose 'video' or 'audio'.")

    # Check if the URL is a Playlist URL
    if "index=" in url.lower() or "list=" in url.lower():
        print("This is URL of a Playlist , Please choose the appropriate option.")
        isPlaylistDl = input("Do you want to download the playlist? (yes/no): ").strip().lower() == "no"


    # Base command
    command = [
        "yt-dlp",
        "-f", format_string,
        "--write-auto-sub",
        "--sub-lang", subtitle_lang,
        "--output", save_path,
        url
    ]

    if isPlaylistDl:
        command.append("--yes-playlist")
    else:
        command.append("--no-playlist")

    subprocess.run(command)

def ask_save_path():
    root = tk.Tk()
    root.withdraw()
    save_path = filedialog.asksaveasfilename(defaultextension=".mp4", # noqa
                                             filetypes=[("MP4 files", "*.mp4"), ("All files", "*.*")])
    return save_path

if __name__ == "__main__":
    # Example usage
    url = input("Enter the video URL: ")

    resolution = input("Enter the resolution (e.g., 720): ")
    subtitle_lang = input("Enter the subtitle language (e.g., fa): ")
    download_type = input("Enter the download type (video/audio): ").lower()

    # Get save path from user
    save_path = ask_save_path()
    if not save_path:
        print("No save path selected. Exiting.")
        exit()

    # Option to choose built-in downloader
    # use_builtin_downloader = input ("Use built-in downloader? (yes/no): ").strip().lower() == "yes"

    download_video(resolution, url, subtitle_lang, download_type, save_path)
    subprocess.run(['explorer', '.'])
