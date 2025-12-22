from abc import ABC, abstractmethod

class ImagePathGenerator(ABC):
    """
    Interface for generating text.
    """
    @abstractmethod
    def generate(self) -> str:
        """
        Generate a text string.

        Returns:
        str: The generated text string.
        """
        pass