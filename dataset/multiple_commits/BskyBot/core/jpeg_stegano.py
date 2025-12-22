import subprocess
import os

class JpegStegano:
    
    @staticmethod
    def encode(input_image_path, output_image_path, secret_message):
        """
        Encodes a secret message into the image using the Dockerized steganography tool.
        """
        # Ensure the output file exists as an empty file
        open(output_image_path, "w").close()

        command = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{os.path.abspath(input_image_path)}:/app/input_image.jpg",
            "-v",
            f"{os.path.abspath(output_image_path)}:/app/output_image.jpg",
            "stegano_image",  # Replace with your Docker image name
            "-e",
            "/app/input_image.jpg",
            "/app/output_image.jpg",
            secret_message,
        ]

        try:
            subprocess.run(command, check=True)
            print(f"Secret message encoded into: {output_image_path}")
        except subprocess.CalledProcessError as e:
            print("Docker command failed:", e)
            raise

    @staticmethod
    def decode(input_image_path):
        """
        Decodes a secret message from the image using the Dockerized steganography tool.
        """
        command = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{os.path.abspath(input_image_path)}:/app/image.jpg",
            "stegano_image",  # Replace with your Docker image name
            "-d",
            "/app/image.jpg",
        ]

        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            decoded_message = result.stdout.strip()
            print(f"Decoded message: {decoded_message}")
            return decoded_message
        except subprocess.CalledProcessError as e:
            print("Docker command failed:", e)
            raise