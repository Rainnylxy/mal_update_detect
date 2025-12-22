import yt_dlp


video_url = ""
video_resolution = ""
audio_format = ""
subtitle_lang = ""
embed_subtitle = ""
format_string = ""
download_type = ""

def list_formats(url):
    """List available formats for a given video URL."""
    ydl_opts = {'quiet': True}
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        info_dict = ydl.extract_info(url, download=False)
        formats = info_dict.get('formats', [])

        print("\nAvailable formats:")
        for f in formats:
            # Use .get() to safely access keys that may not exist
            resolution = f.get('height', 'N/A')
            vcodec = f.get('vcodec', 'N/A')
            acodec = f.get('acodec', 'N/A')
            format_id = f.get('format_id', 'N/A')
            print(f"Resolution: {resolution}p | Video codec: {vcodec} | Audio codec: {acodec} | Format ID: {format_id}")



def get_video_specific():
    global video_url, video_resolution, audio_format, subtitle_lang, embed_subtitle, format_string, download_type
    # Get user input
    video_url = input("Enter the YouTube video URL: ")
    # List available formats for user reference
    list_formats(video_url)

    # Ask for user preference between video or audio download
    download_type = input("\nDo you want to download 'video' or 'audio' only? ").strip().lower()

    # Set video-specific inputs if needed
    if download_type == 'video':
        video_resolution = input("Enter the desired video resolution (e.g., 720, 1080): ")
        format_string = f'bestvideo[height<={video_resolution}]+bestaudio/best[height<={video_resolution}]'
    else:
        # For audio-only download
        audio_format = input("Enter the desired audio format (e.g., mp3, m4a, best): ")
        format_string = f'bestaudio'

    subtitle_lang = input("Enter the subtitle language code (e.g., en for English, fa for Persian, leave empty if not needed): ")
    embed_subtitle = input("Do you want to embed subtitles in the video? (yes/no): ").lower() == "yes"

def download_youtube_video():
    get_video_specific()

    # Configure yt-dlp options based on the download type
    ydl_opts = {
        'format': format_string,

        # Post-processing for audio if needed
        'postprocessors': [{
            'key': 'FFmpegExtractAudio',
            'preferredcodec': audio_format,
            'preferredquality': '192',
        }] if download_type == 'audio' else [],

        # Subtitle options
        'writesubtitles': True if subtitle_lang else False,
        'subtitleslangs': [subtitle_lang] if subtitle_lang else [],
        'subtitlesformat': 'vtt',
        'embedsubtitles': True if embed_subtitle else False,
    }

    # Download the video using the selected options
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([video_url])
            print("Download complete!")
    except yt_dlp.utils.ExtractorError as e:
        print(f"An error occurred: {e}. Please ensure the chosen resolution is available.")


# Optional: Define a download progress hook to show progress in the terminal
def download_progress(d):
    if d['status'] == 'downloading':
        print(f"Downloading... {d['_percent_str']} of {d['_total_bytes_str']} at {d['_speed_str']} ETA: {d['_eta_str']}")
    elif d['status'] == 'finished':
        print(f"Download completed! File saved to: {d['filename']}")

# Run the downloader
download_youtube_video()
