
from atproto import Client as AtClient, models

class MyPost:
    def __init__(self, uri, cid, text, image_alt, created):
        self.uri = uri
        self.cid = cid
        self.text = text
        self.image_alt = image_alt
        self.created = created
        
    def __str__(self):
        return f"MyPost(uri={self.uri}, cid={self.cid}, text={self.text}, image_alt={self.image_alt}, created={self.created})"


class BskyClient:
    def __init__(self, handle, password, did):
        # self.bs_client = BsClient() # client for posting
        self.client = AtClient() # client for fetching
        self.client.login(handle, password)
        self.did = did

    def create_post(self, text: str, image_path: str = None, image_alt: str = None):
        """
        Create a post on Bluesky with optional images.

        Parameters:
        text (str): The text content of the post.
        image_path (str, optional): The path to the image file.
        image_alt (str, optional): The alt text for the image.

        Returns:
        dict: The response from the Bluesky API after posting.
        """
        if image_path and not image_alt:
            raise ValueError("If image_path is provided, image_alt must also be provided.")

        # Add image if provided
        if image_path:
            with open(image_path, 'rb') as img_file:
                img_data = img_file.read()
            image = self.client.upload_blob(img_data)
            post_embed = models.AppBskyEmbedImages.Main(
                images=[
                    models.AppBskyEmbedImages.Image(
                        alt=image_alt,
                        image=image.blob
                    )
                ]
            )
        else:
            post_embed = None

        # Send the post
        post =  self.client.send_post(
            text=text,
            embed=post_embed
        )
        
        return MyPost(post.uri, post.cid, text, image_alt, None)

    def create_reply(self, root: MyPost, parent: MyPost, text: str, image_path: str = None, image_alt: str = None):
        """
        Create a reply to a post on Bluesky.

        Parameters:
        root (dict): The root post of the thread.
        parent (dict): The parent post to reply to.
        text (str): The text content of the reply.
        image_path (str, optional): The path to the image file.
        image_alt (str, optional): The alt text for the image.

        Returns:
        dict: The response from the Bluesky API after posting the reply.
        """
        if image_path and not image_alt:
            raise ValueError("If image_path is provided, image_alt must also be provided.")

        # Create strong references for root and parent
        root_ref = models.create_strong_ref(root)
        parent_ref = models.create_strong_ref(parent)

        # Prepare the reply reference
        reply_ref = models.AppBskyFeedPost.ReplyRef(parent=parent_ref, root=root_ref)

        # Add image if provided
        if image_path:
            with open(image_path, 'rb') as img_file:
                img_data = img_file.read()
            image = self.client.upload_blob(img_data)
            post_embed = models.AppBskyEmbedImages.Main(
                images=[
                    models.AppBskyEmbedImages.Image(
                        alt=image_alt,
                        image=image.blob
                    )
                ]
            )
        else:
            post_embed = None

        # Send the reply
        reply = self.client.send_post(
            text=text,
            reply_to=reply_ref,
            embed=post_embed
        )
        
        return MyPost(reply.uri, reply.cid, text, image_alt, None)
        
    def read_thread(self, uri: str, depth: int = 1000, parent_height: int = 1000) -> list[MyPost]:
        """
        Fetch and parse a thread from Bluesky.

        Parameters:
        uri (str): The URI of the root post to fetch the thread.
        depth (int, optional): The depth of descendant posts to fetch. Defaults to 6.
        parent_height (int, optional): The height of ancestor posts to fetch. Defaults to 80.

        Returns:
        list[dict]: A list of replies sorted by time (ascending), containing text and image alt.
        """
        res = self.client.get_post_thread(uri=uri, depth=depth, parent_height=parent_height)
        thread = res.thread
        
        replies = self._parse_posts(thread.replies)
        
        return replies
    
    def read_posts_latest(self, limit: int = 1) -> list[MyPost]:
        data = self.client.get_author_feed(
                actor=self.did,
                filter="posts_no_replies",
                limit=limit,
            )

        return self._parse_posts(data.feed)
    
    def _parse_posts(self, posts: list) -> list[MyPost]:
        """
        Parse posts into sorted MyPost objects.

        Parameters:
        posts (list): The list of posts to parse.

        Returns:
        list[MyPost]: Sorted list of MyPost objects by created time.
        """
        parsed_posts = []

        for post in posts or []:
            try:
                uri = post.post.uri
                cid = post.post.cid
                text = post.post.record.text
                created = post.post.record.created_at

                embed = getattr(post.post.record, 'embed', None)
                image_alt = embed.images[0].alt if embed and getattr(embed, 'images', None) else None

                parsed_posts.append(MyPost(uri, cid, text, image_alt, created))
            except AttributeError:
                continue

        return sorted(parsed_posts, key=lambda x: x.created)

if __name__ == "__main__":
    bsky_client = BskyClient()

    # Example usage:
    try:
        # Create a post
        # post_response = bsky_client.create_post(
        #     text="This is a new post with an image",
        #     image_path="prepared_image.jpg",
        #     image_alt="The image"
        # )
        # print("Post created:", post_response)

        # # Create a reply to the root post
        # reply_response = bsky_client.create_reply(
        #     root=post_response,
        #     parent=post_response,
        #     text="This is a reply to the root post!",
        #     image_path=None,
        #     image_alt=None
        # )
        # print("Reply created:", reply_response)

        # # Reply to post
        # second_reply_response = bsky_client.create_reply(
        #     root=post_response,
        #     parent=post_response,
        #     text="This is a reply to the post with image!",
        #     image_path="prepared_image.jpg",
        #     image_alt="second reply imgae"
        # )
        # print("Second reply created:", second_reply_response)
        
        # thread_replies = bsky_client.read_thread(uri="at://did:plc:ybleilw4bhtsiupfiozibvfq/app.bsky.feed.post/3lejsu5tojg2e")
        # print("Thread replies:", thread_replies)

        print(bsky_client.read_posts_latest(1))
        
        pass
        
    except Exception as e:
        print("Error:", e)