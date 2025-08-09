import sys
import os
import hashlib
import requests
import time
import dotenv
dotenv.load_dotenv(),
API_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": os.getenv("VIRUSTOTAL_API_KEY")
}

def is_url(path):
    return path.startswith("http://") or path.startswith("https://")

def sha256_of_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def get_file_report(file_hash):
    url = f"{API_URL}/files/{file_hash}"
    r = requests.get(url, headers=HEADERS)
    if r.status_code == 200:
        return r.json()
    else:
        return None

def upload_file(filepath):
    url = f"{API_URL}/files"
    with open(filepath, "rb") as f:
        files = {"file": (os.path.basename(filepath), f)}
        r = requests.post(url, headers=HEADERS, files=files)
    if r.status_code == 200:
        return r.json()
    else:
        print(f"Upload failed: {r.status_code} {r.text}")
        return None

def get_url_report(url_id):
    url = f"{API_URL}/urls/{url_id}"
    r = requests.get(url, headers=HEADERS)
    if r.status_code == 200:
        return r.json()
    else:
        return None

def scan_url(url_to_scan):
    api_endpoint = f"{API_URL}/urls"
    data = {"url": url_to_scan}
    r = requests.post(api_endpoint, headers=HEADERS, data=data)
    if r.status_code == 200:
        return r.json()
    else:
        print(f"URL scan failed: {r.status_code} {r.text}")
        return None

def main():
    if len(sys.argv) != 2:
        print("Usage: checkvirus PATH_OR_URL")
        sys.exit(1)

    target = sys.argv[1]

    if is_url(target):
        print(f"Scanning URL: {target}")
        result = scan_url(target)
        if not result:
            sys.exit(1)
        url_id = result['data']['id']  # This is the URL identifier used in VT
        print("Waiting for scan results...")
        time.sleep(15)  # Simple wait, better to implement polling

        report = get_url_report(url_id)
        if not report:
            print("No report found.")
            sys.exit(1)

        stats = report['data']['attributes']['last_analysis_stats']
        print(f"Detections: {stats['malicious']} malicious out of {stats['total']}")
    else:
        # File scan path
        if not os.path.isfile(target):
            print("File does not exist.")
            sys.exit(1)

        file_hash = sha256_of_file(target)
        print(f"File SHA256: {file_hash}")

        report = get_file_report(file_hash)
        if report:
            print("Report found for this file.")
        else:
            print("No report found, uploading file...")
            upload_result = upload_file(target)
            if not upload_result:
                sys.exit(1)
            print("File uploaded, waiting for analysis...")
            time.sleep(30)  # Wait for the scan, can implement polling for real

            report = get_file_report(file_hash)
            if not report:
                print("No report available after upload.")
                sys.exit(1)

        stats = report['data']['attributes']['last_analysis_stats']
        print(f"Detections: {stats['malicious']} malicious out of {stats['total']}")

if __name__ == "__main__":
    main()
