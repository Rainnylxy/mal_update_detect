class HeaderSerializer:
    @staticmethod
    def serialize(id: str, type: str, curr_post: int, total_posts: int):
        """
        Serialize the provided parameters into a header string format.

        Parameters:
        id (str): The unique identifier for the request/response.
        type (str): The type of the message ('req' for request, 'res' for response).
        curr_post (int): The current post index (1-based).
        total_posts (int): The total number of posts in the request/response.

        Returns:
        str: Serialized header string in the format 'id,type,curr_post,total_posts'.
        """
        if not isinstance(id, str) or not isinstance(type, str):
            raise ValueError("id and type must be strings.")

        if not isinstance(curr_post, int) or not isinstance(total_posts, int):
            raise ValueError("curr_post and total_posts must be integers.")

        # Convert type to '0' for 'req' and '1' for 'res'
        if type == 'req':
            type = '0'
        elif type == 'res':
            type = '1'
        else:
            raise ValueError("type must be 'req' or 'res'.")

        return f"{id},{type},{curr_post},{total_posts}"

    @staticmethod
    def deserialize(header_str: str):
        """
        Deserialize a header string into its components.

        Parameters:
        header_str (str): The header string in the format 'id,type,curr_post,total_posts'.

        Returns:
        dict: A dictionary with keys 'id', 'type', 'curr_post', and 'total_posts'.
        """
        parts = header_str.split(",")
        if len(parts) != 4:
            raise ValueError("Invalid header format. Expected format: 'id,type,curr_post,total_posts'.")

        try:
            type_ = 'req' if parts[1] == '0' else 'res' if parts[1] == '1' else None
            if type_ is None:
                raise ValueError("type must be '0' for 'req' or '1' for 'res'.")

            return {
                "id": parts[0],
                "type": type_,
                "curr_post": int(parts[2]),
                "total_posts": int(parts[3])
            }
        except ValueError:
            raise ValueError("curr_post and total_posts must be integers.")

# Example usage
if __name__ == "__main__":

    # Serialize the header
    serialized_header = HeaderSerializer.serialize("1nbk3", "req", 1, 2)
    print("Serialized Header:", serialized_header)

    # Deserialize the header
    deserialized_header = HeaderSerializer.deserialize(serialized_header)
    print("Deserialized Header:", deserialized_header)
