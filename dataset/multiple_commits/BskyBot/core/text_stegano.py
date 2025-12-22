import pyUnicodeSteganography as usteg

class TextStegano:
    @staticmethod
    def encode(text: str, secret: str) -> str:
        """
        Encodes a secret message into the image using the Dockerized steganography tool.
        """
        return str(usteg.encode(text, secret, method="zw"))

    @staticmethod
    def decode(text: str) -> str:
        """
        Decodes a secret message from the image using the Dockerized steganography tool.
        """
        return str(usteg.decode(text, method="zw"))

# if __name__ == "__main__":
    # stg = TextStegano()
    
    # ZW method:        secret max cca n = 74 chars long with text n+1     long to produce <= 300 long message - robost and most efficient
    # SNOW method:      secret max cca n = 36 chars long with text       1 long to produce <= 300 long message - robust, very inefficient
    # LOOKALIKE method: secret max cca n = 30 chars long with text cca 300 long to produce <= 300 long message - not robust, not efficient, visible
    
    # ZW limit is n = 77
    # text =   "Achieve more with a smart solutions designed to empower and inspire journey! !"
    # secret = "Innovate, simplify and succeed with tools designed for your growth! Today.! !"
    # print("text len:", len(text))
    # print("secret len:", len(secret))
    # encoded = stg.encode(text, secret)
    # decoded = stg.decode(encoded)
    # print(encoded)