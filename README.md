# VirusTotalScan

Bulk scan and upload files/hashes to [VirusTotal](www.virustotal.com).

## Requirements

* Python 3
* [VirusTotal API Key](https://developers.virustotal.com/reference#getting-started) 
* [Requests Module](https://pypi.org/project/requests/)

## Usage

```python
vts.py [-h] -k API -f FILE [-u] [-d DELAY] -o OUTPUTFILE [-r MAXRETRY]

optional arguments:
  -h, --help            show this help message and exit
  -k API, --api API     VirusTotal API Key
  -f FILE, --file FILE  File to be scanned
  -u, --upload          Enable uploading file to Virustotal
  -d DELAY, --delay DELAY
                        Delay in seconds after API limit reached or scan result is not ready
  -o OUTPUTFILE, --outputfile OUTPUTFILE
                        Output file in csv format. 
                        If the file already exists, hashes listed in the file will be skipped
  -r MAXRETRY, --maxretry MAXRETRY
                        Max number of request retries to Virustotal API

```

### Note:
* Re-running the script with the same output file will not overwrite the file. Instead, the script will scan the output file and skip previously scanned hashes


## Examples

Scanning single file (hash only):
```python 
./vts.py -k YOUR_API_KEY -f ./file.exe -o ./output.csv 
```

Scanning all files (hashes only) in a directory (including subdirectory):
```python 
./vts.py -k YOUR_API_KEY -f ./ -o ./output.csv 
```

Upload file to VirusTotal and Scan:
```python 
./vts.py -k YOUR_API_KEY -f ./file.exe -o ./output.csv -u
```

Upload all files in a directory (including subdirectory) to VirusTotal and Scan:
```python 
./vts.py -k YOUR_API_KEY -f ./file.exe -o ./output.csv -u
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

