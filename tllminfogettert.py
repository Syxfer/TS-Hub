import discord
import asyncio
import requests
import json
from datetime import datetime

async def get_invite_link():
    invite_link = input("Please enter the invite link to the Discord server: ")
    print("\nMake sure you have joined the server using this invite link and are currently logged into Discord in your browser or the desktop application.")
    input("Press Enter to proceed after joining the server...")
    return invite_link

async def get_channel_id():
    channel_id_str = input("Please enter the ID of the Discord channel you want to extract messages from: ")
    try:
        channel_id = int(channel_id_str)
        return channel_id
    except ValueError:
        print("Invalid channel ID. Please enter a numeric ID.")
        return None

async def get_discord_token():
    discord_token = input("Please enter your Discord user token: ")
    print("\nWarning: User tokens are sensitive and should be handled with extreme care.")
    return discord_token

async def get_webhook_url():
    webhook_url = input("Please enter the Discord webhook URL: ")
    return webhook_url

async def fetch_and_format_messages(channel, headers):
    messages = []
    async for message in channel.history(limit=None, oldest_first=True):
        timestamp = message.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')
        content = message.content
        author = message.author.name
        formatted_message = f"[{timestamp}] {author}: {content}\n"
        messages.append(formatted_message)
    return "".join(messages)

async def send_to_webhook(webhook_url, formatted_messages):
    data = {
        "content": f"**--- Channel Message History ---**\n```\n{formatted_messages}\n```"
    }
    headers = {
        'Content-Type': 'application/json'
    }
    try:
        response = requests.post(webhook_url, data=json.dumps(data), headers=headers)
        response.raise_for_status()
        print("Messages sent to the webhook successfully!")
    except requests.exceptions.RequestException as e:
        print(f"Error sending to webhook: {e}")

async def main():
    invite_link = await get_invite_link()
    channel_id = await get_channel_id()
    if channel_id is None:
        return
    discord_token = await get_discord_token()
    webhook_url = await get_webhook_url()

    headers = {
        'Authorization': discord_token
    }

    async with discord.Client(headers=headers) as client:
        channel = await client.fetch_channel(channel_id)
        if channel:
            print(f"Fetching messages from channel: {channel.name} (ID: {channel.id})")
            formatted_messages = await fetch_and_format_messages(channel, headers)
            await send_to_webhook(webhook_url, formatted_messages)
        else:
            print(f"Error: Could not find channel with ID {channel_id}.")

if __name__ == "__main__":
    asyncio.run(main())