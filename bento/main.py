import os
import requests
from .config import get_api_key

API_URL = 'https://www.virustotal.com/vtapi/v2/'

def process_input(input_value):
    if os.path.isfile(input_value):
        scan_file(input_value)
    else:
        scan_url(input_value)

def scan_file(file_path):
    api_key = get_api_key()
    url = API_URL + 'file/scan'
    with open(file_path, 'rb') as f:
        files = {'file': (os.path.basename(file_path), f)}
        params = {'apikey': api_key}
        resp = requests.post(url, files=files, params=params)
    print_response(resp)

def scan_url(url_to_scan):
    api_key = get_api_key()
    url = API_URL + 'url/scan'
    params = {'apikey': api_key, 'url': url_to_scan}
    resp = requests.post(url, data=params)
    print_response(resp)

def print_response(resp):
    try:
        resp.raise_for_status()
        data = resp.json()
        for k, v in data.items():
            print(f"{k}: {v}")
    except Exception as e:
        print(f"Error: {e}\nResponse: {resp.text}")
