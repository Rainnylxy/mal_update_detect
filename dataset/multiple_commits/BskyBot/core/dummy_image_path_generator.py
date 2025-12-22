import os
import random

from core.image_path_generator import ImagePathGenerator

class DummyImagePathGenerator(ImagePathGenerator):
    """
    Generates random image paths from a predefined directory.
    """
    def __init__(self, directory: str):
        """
        Initialize the generator with a directory path.

        Parameters:
        directory (str): The directory containing image files.
        """
        if not os.path.isdir(directory):
            raise ValueError(f"The specified directory does not exist: {directory}")

        self.directory = directory

    def generate(self) -> str:
        """
        Select a random image file from the directory.

        Returns:
        str: The path to a randomly selected image file.
        """
        images = [f for f in os.listdir(self.directory) if os.path.isfile(os.path.join(self.directory, f))]
        if not images:
            raise ValueError(f"No image files found in directory: {self.directory}")

        return os.path.join(self.directory, random.choice(images))