# BskyBot
Bluesky bot is a simulation of a malicious bot communicating purely through Bluesky social. The purpose of it is solely educational

This project is part of the CTU BSY class - 2024 bonus assignment.

## Assignment fulfillment examples

- list users: `python3 controller.py w`

- list directory: `python3 controller.py ls`

- bot user id: `python3 controller.py id`

- create file: `python3 controller.py "echo 'echo Jeden prsten vládne všem' > prsten"`

- chmod that file: `python3 controller.py 'chmod +x prsten'`

- execute that file: `python3 controller.py './prsten'`

- download that file: `python3 controller.py "base64 -i prsten" | base64 --decode > prsten_copy`

    (Tested also with larger files - 1 MB image takes approx. 80 replies.)

- remove that file: `python3 controller.py 'rm prsten'`

- check the bot presence: `python3 controller.py 'echo Hodíte mi očkem po Frodovi?' -t 30`

    (Set the timeout to 30 seconds and wait for echo.)

## Usage

1) create a venv and install a requirments

    __note:__ `Python3.13.1` was used for development

2) create a `.env` file with the following variables

    ```
    BSKY_LOGIN="yourname.bsky.social"
    BSKY_PASSWORD="YourPassword"
    BSKY_DID="yourDidHandle"
    ```

    You can get the DID with the following endpoint:

    ```
    https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=yourname.bsky.social
    ```

3) create an image database

    Both `bot.py` and `controller.py` require an `image_db` directory in the root of the project. They randomly pick an image from there for every request or response.
    
    Each image is automatically processed to meet the social network requirements

4) start the bot

    `python3 bot.py`

5) use the controller to send a command

    `python3 controller.py <command>`

    the command can be any Linux-based command:

    `python3 controller.py ls`

    `python3 controller.py 'cat README.md'`

## About

### Protocol

The communication is client/server request/response, where the bot is the server and the controller is the client.

__Request__ is a Bluesky post.

__Response__ is a set of replies to that post.

```
     ┌────┐           ┌──────────┐           ┌────┐           ┌───┐           ┌─────┐
     │User│           │Controller│           │Bsky│           │Bot│           │Linux│
     └──┬─┘           └─────┬────┘           └──┬─┘           └─┬─┘           └──┬──┘
        │     Command       │                   │               │                │   
        │──────────────────>│                   │               │                │   
        │                   │                   │               │                │   
        │                   │                   │  Check feed   │                │   
        │                   │                   │<──────────────│                │   
        │                   │                   │               │                │   
        │                   │       Post        │               │                │   
        │                   │──────────────────>│               │                │   
        │                   │                   │               │                │   
        │                   │  Check replies    │               │                │   
        │                   │──────────────────>│               │                │   
        │                   │                   │               │                │   
        │                   │                   │  Check feed   │                │   
        │                   │                   │<──────────────│                │   
        │                   │                   │               │                │   
        │                   │                   │  Fetch post   │                │   
        │                   │                   │──────────────>│                │   
        │                   │                   │               │                │   
        │                   │                   │               │Execute command │   
        │                   │                   │               │───────────────>│   
        │                   │                   │               │                │   
        │                   │                   │               │Command output  │   
        │                   │                   │               │<───────────────│   
        │                   │                   │               │                │   
        │                   │                   │  Reply 1/n    │                │   
        │                   │                   │<──────────────│                │   
        │                   │                   │               │                │   
        │                   │  Check replies    │               │                │   
        │                   │──────────────────>│               │                │   
        │                   │                   │               │                │   
        │                   │ Fetch reply 1/n   │               │                │   
        │                   │<──────────────────│               │                │   
        │                   │                   │               │                │   
        │                   │                   │  Reply n/n    │                │   
        │                   │                   │<──────────────│                │
        │                   │                   │               │                │ 
        │                   │  Check replies    │               │                │   
        │                   │──────────────────>│               │                │   
        │                   │                   │               │                │  
        │                   │ Fetch reply n/n   │               │                │   
        │                   │<──────────────────│               │                │   
        │                   │                   │               │                │   
        │  Command output   │                   │               │                │   
        │<──────────────────│                   │               │                │   
     ┌──┴─┐           ┌─────┴────┐           ┌──┴─┐           ┌─┴─┐           ┌──┴──┐
     │User│           │Controller│           │Bsky│           │Bot│           │Linux│
     └────┘           └──────────┘           └────┘           └───┘           └─────┘
```

Each __request__ and __response__ (response partition) consists of __header__ and __data__.

__Header__ is encoded in the actual text of the post using lingual zero-width steganography.

__Data__ are encoded with Base64 and put in a post's image's alt text.

Meaning every post and reply to that post contains a text and an image.
