# VirusTotalScan

Bulk scan and upload files/hashes to [VirusTotal](www.virustotal.com).

## Requirements

* Python 3
* [VirusTotal API Key](https://developers.virustotal.com/reference#getting-started) 
* [Requests Module](https://pypi.org/project/requests/)

## Usage

```bash
vts.py [-h] -k API -f FILE [-x EXCLUDEDFILES] [-u] [-U] [-d DELAY] -o
              OUTPUTFILE [-r MAXRETRY]

optional arguments:
  -h, --help            show this help message and exit
  -k API, --api API     VirusTotal API Key
  -f FILE, --file FILE  File to be scanned
  -x EXCLUDEDFILES, --excludedfiles EXCLUDEDFILES
                        File containing list of files to be excluded
                        (separated by newline)
  -u, --upload          Enable uploading file and scan to Virustotal
  -U, --uploadonly      Enable upload only to Virustotal
  -d DELAY, --delay DELAY
                        Delay in seconds after API limit reached or scan
                        result is not ready
  -o OUTPUTFILE, --outputfile OUTPUTFILE
                        Output file in csv format. If the file already exists,
                        hashes listed in the file will be skipped
  -r MAXRETRY, --maxretry MAXRETRY
                        Max number of request retries to Virustotal API

```

## Examples

Scanning single file (hash only):
```bash 
./vts.py -k YOUR_API_KEY -f ./file.exe -o ./output.csv 
```

Scanning all files (hashes only) in a directory (including subdirectory):
```bash 
./vts.py -k YOUR_API_KEY -f ./ -o ./output.csv 
```

Upload file to VirusTotal and Scan:
```bash 
./vts.py -k YOUR_API_KEY -f ./file.exe -o ./output.csv -u
```

Upload all files in a directory (including subdirectory) to VirusTotal and Scan:
```bash 
./vts.py -k YOUR_API_KEY -f ./ -o ./output.csv -u
```

Upload file to VirusTotal without scanning:
```bash 
./vts.py -k YOUR_API_KEY -f ./file.exe -o ./output.csv -U
```

Upload all files in a directory (including subdirectory) to VirusTotal without scanning:
```bash 
./vts.py -k YOUR_API_KEY -f ./ -o ./output.csv -U
```

Scanning single file (hash only) with exclusion list:
```bash 
./vts.py -k YOUR_API_KEY -f ./file.exe -o ./output.csv -x ./exluded.txt
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

