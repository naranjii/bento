import os

API_KEY_ENV = '67f58b9f689bc42c51912f4cebeaf5ac257a08d4c7e587f3ce1bfea2a992589a'


def get_api_key():
    api_key = os.environ.get(API_KEY_ENV)
    if not api_key:
        raise RuntimeError(f"VirusTotal API key not set. Please set the {API_KEY_ENV} environment variable.")
    return api_key
