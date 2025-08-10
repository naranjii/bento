<h1><i>🏅 bento </i></h1>
A CLI for scanning files | urls for suspicious activity and malware. Encrypts and sends packages with hash and python requests; Returns details on possible detections.

<h2>🚧🚧🚧🚧 pre-release repo 🚧🚧 🚧🚧</h2>

## example-usage
```sh
bento https://example.com
bento suspicious_file.zip
```
prints:
```sh
File flagged by 0 out of 63 antivirus analysis systems.
bento 1.0
```
## installation
1. Install dependencies:
	 ```sh
     git clone https://github.com/naranjii/bento
	 pip install -r requirements.txt
	 ```
2. Install as a package (editable mode recommended for development):
	 ```sh
	 pip install -e .
	 ```
3. Setup your API key to your environment:
Ensure you're registered @ www.virustotal.com to get an API key.
Insert your key as BENTO_VT_API_KEY in environment variables:

- On Windows (PowerShell):
	```powershell
	$env:BENTO_VT_API_KEY = "YOUR_API_KEY"
	```
- On Linux/macOS:
	```sh
	export BENTO_VT_API_KEY="YOUR_API_KEY"
	```

## query a file | url
```sh
bento <URL_OR_PATH>
```

- If `<URL_OR_PATH>` is a file path, the file will be uploaded for scanning.
- If it is a URL, the URL will be submitted for scanning.

See [VirusTotal API v2.0 docs](https://docs.virustotal.com/v2.0/) for more details.

## roadmap && to-do
```
fix url query
better string detection and debugging messages
if threat is detected forward updated information about 
```