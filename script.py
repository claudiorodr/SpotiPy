# -*- coding: utf-8 -*-

# Sample Python code for youtube.playlists.list
# See instructions for running these code samples locally:
# https://developers.google.com/explorer-help/guides/code_samples#python

import os

import google_auth_oauthlib.flow
import googleapiclient.discovery
import googleapiclient.errors
import youtube_dl
import requests
import json
import base64
from secrets import *

scopes = ["https://www.googleapis.com/auth/youtube.readonly"]


def main():
    # Disable OAuthlib's HTTPS verification when running locally.
    # # *DO NOT* leave this option enabled in production.
    # os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    # api_service_name = "youtube"
    # api_version = "v3"
    # client_secrets_file = "client_secret_1048604022009-f78i3dtd6r9mkpses9o008jvuge0i4d5.apps.googleusercontent.com.json"

    # # Get credentials and create an API client
    # flow = google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file(
    #     client_secrets_file, scopes)
    # credentials = flow.run_console()
    # youtube = googleapiclient.discovery.build(
    #     api_service_name, api_version, credentials=credentials)

    # request = youtube.playlistItems().list(
    #     part="snippet,contentDetails",
    #     maxResults=25,
    #     playlistId="PL83nMBA5ZI6aTpUxf273Tnxkb-YfaGTC0"
    # )
    # response = request.execute()

    # print(response)

    # for song in response["items"]:
    #     url = "https://www.youtube.com/watch?v=" + song["contentDetails"]["videoId"]

    #     video = youtube_dl.YoutubeDL({}).extract_info(url, download=False)
    #     song_tile = video["track"]
    #     song_artist = video["artist"]

    #     if song_artist is None and song_tile is Not None:
    #         song = {
    #             "url" : url,
    #             "artist" : song_artist,
    #             "title" : song_tile
    #         }

    # Spotify - Authorization
    url = "https://accounts.spotify.com/api/token"
    headers = {}
    data = {}

    # Encode as Base64
    message = f"{clientId}:{clientSecret}"
    messageBytes = message.encode('ascii')
    base64Bytes = base64.b64encode(messageBytes)
    base64Message = base64Bytes.decode('ascii')


    headers['Authorization'] = f"Basic {base64Message}"
    data['grant_type'] = "client_credentials"

    r = requests.post(url, headers=headers, data=data)

    token = r.json()['access_token']
    print(token)

if __name__ == "__main__":
    main()
