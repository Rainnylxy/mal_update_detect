import base64

class DataSerializer:
    
    @staticmethod
    def serialize_string(data: str, max_len: int = 2000) -> list[str]:
        """
        Serialize text into base64, dividing into parts if too long.

        Parameters:
        data (str): The input string to serialize.

        Returns:
        list[str]: A list of base64-encoded string parts, each of max_len characters or less.
        """
        input_bytes = data.encode('utf-8')  # Convert string to bytes
        encoded_bytes = base64.b64encode(input_bytes)  # Base64 encode
        encoded_string = encoded_bytes.decode('ascii')  # Decode to ASCII for a short Base64 string

        # Split the base64 string into parts of max_len
        parts = [encoded_string[i:i + max_len] for i in range(0, len(encoded_string), max_len)]
        return parts

    @staticmethod
    def deserialize_string(data: list[str]) -> str:
        """
        Deserialize text from base64 parts.

        Parameters:
        data (list[str]): A list of base64-encoded string parts.

        Returns:
        str: The original decoded string.
        """
        # Join the parts into a single base64 string
        encoded_string = ''.join(data)
        decoded_bytes = base64.b64decode(encoded_string)  # Decode Base64 to bytes
        return decoded_bytes.decode('utf-8')

    @staticmethod
    def serialize_bytes(data: bytes, max_len: int = 2000) -> list[str]:
        """
        Serialize bytes into base64, dividing into parts if too long.

        Parameters:
        data (bytes): The input bytes to serialize.

        Returns:
        list[str]: A list of base64-encoded string parts, each of max_len characters or less.
        """
        encoded_bytes = base64.b64encode(data)  # Base64 encode
        encoded_string = encoded_bytes.decode('ascii')  # Decode to ASCII for a short Base64 string

        # Split the base64 string into parts of max_len
        parts = [encoded_string[i:i + max_len] for i in range(0, len(encoded_string), max_len)]
        return parts
    
    @staticmethod
    def deserialize_bytes(data: list[str]) -> bytes:
        """
        Deserialize bytes from base64 parts.

        Parameters:
        data (list[str]): A list of base64-encoded string parts.

        Returns:
        bytes: The original decoded bytes.
        """
        # Join the parts into a single base64 string
        encoded_string = ''.join(data)
        return base64.b64decode(encoded_string)  # Decode Base64 to bytes

# if __name__ == "__main__":
#     string = "Some texts that might be quite long and need splitting into multiple parts based on max_len."
#     ser = DataSerializer(max_len=20)

#     # Text serialization
#     encoded_parts = ser.serialize_string(string)
#     print("Encoded Parts with Lengths:")
#     for part in encoded_parts:
#         print(f"Part: {part} (Length: {len(part)})")
#     decoded = ser.deserialize_string(encoded_parts)
#     print("Decoded String:", decoded)

#     # Bytes serialization
#     byte_data = b"Some binary data that needs to be serialized and split into parts."
#     encoded_byte_parts = ser.serialize_bytes(byte_data)
#     print("Encoded Byte Parts with Lengths:")
#     for part in encoded_byte_parts:
#         print(f"Part: {part} (Length: {len(part)})")
#     decoded_bytes = ser.deserialize_bytes(encoded_byte_parts)
#     print("Decoded Bytes:", decoded_bytes)
