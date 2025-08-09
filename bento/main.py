def format_report(data):
    scans = data.get('scans', {})
    positives = data.get('positives', 0)
    total = data.get('total', len(scans))
    print(f"\nFile detected by {positives} out of {total} antivirus analysis systems.")
    if scans:
        for engine, result in scans.items():
            if result.get('detected'):
                res = result.get('result') or 'malicious'
                print(f"{engine}: {res}")
    print("bento 1.0") 

import os
import requests
from .config import get_api_key

API_URL = 'https://www.virustotal.com/vtapi/v2/'

def process_input(input_value):
    if os.path.isfile(input_value):
        print(f"Sent ({input_value}) as encrypted package to queue...")
        scan_file(input_value)
    else:
        print(f"Sent ({input_value}) as encrypted package to queue...")
        scan_url(input_value)

def scan_file(file_path):
    api_key = get_api_key()
    url = API_URL + 'file/scan'
    with open(file_path, 'rb') as f:
        files = {'file': (os.path.basename(file_path), f)}
        params = {'apikey': api_key}
        resp = requests.post(url, files=files, params=params)
    data = resp.json()
    # Do not print all metadata here
    if data and 'resource' in data:
        print("\nRetrieving report...")
        get_report(data['resource'], is_file=True)

def scan_url(url_to_scan):
    api_key = get_api_key()
    url = API_URL + 'url/scan'
    params = {'apikey': api_key, 'url': url_to_scan}
    resp = requests.post(url, data=params)
    data = resp.json()
    # Print all metadata for URL
    if data and 'resource' in data:
        print("\nRetrieving report...")
        get_report(data['resource'], is_file=False)

def get_report(resource, is_file):
    api_key = get_api_key()
    url = API_URL + 'file/report'
    params = {'apikey': api_key, 'resource': resource}
    resp = requests.get(url, params=params)
    try:
        resp.raise_for_status()
        data = resp.json()
        if is_file:
            format_report(data)
        else:
            # For URLs, print the full report as-is
            for k, v in data.items():
                print(f"{k}: {v}")
    except Exception as e:
        print(f"Error fetching report: {e}\nResponse: {resp.text}")