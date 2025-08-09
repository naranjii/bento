# Bento

A CLI for VirusTotal API v2.0

## Installation

1. Install dependencies:
	 ```sh
	 pip install -r requirements.txt
	 ```
2. Install as a package (editable mode recommended for development):
	 ```sh
	 pip install -e .
	 ```

## API Key Setup

Set your VirusTotal API key as an environment variable:

- On Windows (PowerShell):
	```powershell
	$env:BENTO_VT_API_KEY = "YOUR_API_KEY"
	```
- On Linux/macOS:
	```sh
	export BENTO_VT_API_KEY="YOUR_API_KEY"
	```

## Usage

Query a URL or file:

```sh
bento <URL_OR_PATH>
```

- If `<URL_OR_PATH>` is a file path, the file will be uploaded for scanning.
- If it is a URL, the URL will be submitted for scanning.

## Example

```sh
bento https://example.com
bento suspicious_file.zip
```

See [VirusTotal API v2.0 docs](https://docs.virustotal.com/v2.0/) for more details.