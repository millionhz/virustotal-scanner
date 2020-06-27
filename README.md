# VirusTotal Command-Line Scanner

A command-line utility to scan files through the VirusTotal API v3

## Setting Up

### Dependencies

The script uses the requests module. You can download the module by running the following command:

```code
pip install requests
```

### API Key

The script uses the VirusTotal API. In order to use the API you must sign up to [VirusTotal Community](https://www.virustotal.com/gui/join-us). Once you have a valid VirusTotal Community account you will find your personal API key in your personal settings section. This key is all you need to use the VirusTotal API

Once you have the API key you will need to put it in the `virustotal.py` file, right were it says `"add your API key here"`:

```python
try:
    from key import API_KEY
except:
    API_KEY = "add your API key here"
```

You can also put the API Key in another python file and import it.

NOTE: Do not share your API Key with anyone. Learn more about securing an API key [here.](https://cloud.google.com/docs/authentication/api-keys#securing_an_api_key)

## Usage

```code
usage: virustotal.py [-h] file
```

### Scanning a file

You scan a file by providing the file path to it.

```code
virustotal.py ~/home/scan_me.exe
```

## How does the script work

The script uses VirusTotal API to scan files.

The script makes a GET request with the SHA 256 hash of the file. If no information about the file is returned or a 404 response code is sent back, then the script will upload the file to VirusTotal and wait for the analysis report. Once the analysis report is available, the script will again make a GET request against the SHA 256 of the same file and display the output.

As of now, the output is in form of JSON data. This will be changed later.
