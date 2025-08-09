import os

API_KEY_ENV = 'BENTO_VT_API_KEY'


def get_api_key():
    api_key = os.environ.get(API_KEY_ENV)
    if not api_key:
        raise RuntimeError(f"VirusTotal API key not set. Please set the {API_KEY_ENV} environment variable.")
    return api_key
