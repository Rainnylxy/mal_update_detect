from PIL import Image
import os

class ImageProcessor:
        
    @staticmethod
    def compress_bsky(input_image_path, output_image_path, max_size=500):
        """
        Prepare the image for Bluesky by resizing, compressing, and stripping metadata to meet size and file size constraints.

        :param input_image_path: Path to the input image.
        :param output_image_path: Path to save the processed image.
        :param max_size: Maximum dimension for the larger side of the image (default: 500 pixels).
        """
        # Ensure the output directory exists
        output_dir = os.path.dirname(output_image_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Ensure the output file exists
        if not os.path.exists(output_image_path):
            open(output_image_path, 'a').close()
            
        with Image.open(input_image_path) as img:
            # Preserve aspect ratio and resize if necessary
            img = img.convert("RGB")  # Ensure the image is in RGB mode
            width, height = img.size
            if max(width, height) > max_size:
                scaling_factor = max_size / max(width, height)
                new_width = int(width * scaling_factor)
                new_height = int(height * scaling_factor)
                img = img.resize((new_width, new_height), Image.LANCZOS)
                # print(f"Image resized to {new_width}x{new_height}")

            # Save the image without metadata
            img.save(
                output_image_path,
                format="JPEG",
                quality=95,
                progressive=False,
                subsampling="4:2:0",
                optimize=True,
            )

            # file_size_mb = os.path.getsize(output_image_path) / (1024 * 1024)
