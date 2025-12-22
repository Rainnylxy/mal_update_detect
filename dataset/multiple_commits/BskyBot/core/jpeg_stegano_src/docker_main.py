import sys
from steganography.steganography import Steganography

if len(sys.argv) < 3:
    print("Usage:")
    print("  Encode: python stegano_script.py -e <input_image> <output_image> <text>")
    print("  Decode: python stegano_script.py -d <image>")
    sys.exit(1)

if sys.argv[1] == "-e":
    # Encode text into an image
    input_image = sys.argv[2]
    output_image = sys.argv[3]
    text = sys.argv[4]
    Steganography.encode(input_image, output_image, text)
    print("Encoded text into {}".format(output_image))

elif sys.argv[1] == "-d":
    # Decode text from an image
    image = sys.argv[2]
    decoded_text = Steganography.decode(image)
    print("Decoded text: {}".format(decoded_text))

else:
    print("Invalid option. Use -e to encode or -d to decode.")
