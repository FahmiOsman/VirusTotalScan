#!/usr/bin/env python
# encoding: utf-8
import requests
import argparse
import json
import os
import hashlib
import time
import csv

def sha256(filename):
	sha256_hash = hashlib.sha256()
	with open(filename,'rb') as f:	
		for byte_block in iter(lambda: f.read(4096),b""):
			sha256_hash.update(byte_block)
	
		return sha256_hash.hexdigest()

def scanHash(apikey, filehash,maxRetry,delay):
	"""
	Return: 
		response_code = 0 : hash not found
		response_code = 1 : scan successful
		response_code = -1 : max retry reached
	"""

	url = 'https://www.virustotal.com/vtapi/v2/file/report'	
		
	data = {'apikey': apikey, 'resource': filehash}	
	print("   Scanning...")

	for attempt in range(maxRetry):
		r = requests.post(url, data=data)
		if r.status_code == 200:
			parsed_json =  json.loads(r.text)
			if parsed_json['response_code'] == 0:
				print("   Hash not found in Virustotal. You may try to include -u in the argument to upload the file")
				return {"response_code" : 0}
			if parsed_json['response_code'] == -2:
				print("   Scan results not ready. Retrying in "+str(delay)+" seconds")
				time.sleep(delay)
				continue
			
			print("   "+str(parsed_json['positives']) + "/" + str(parsed_json['total']) + " AVs detected")
			response = {"response_code" : 1, 
					 "sha256": parsed_json['sha256'], 
					 "permalink" : parsed_json['permalink'],
					 "positives" : str(parsed_json['positives']),
					 "total" : str(parsed_json['total'])}
				
			scans = ""
			for x in parsed_json['scans']:
				if parsed_json['scans'][x]['detected']:
					print("   "+ x+": "+ parsed_json['scans'][x]['result'])
					scans = scans + x+": "+ parsed_json['scans'][x]['result'] + "; "

			response["scans"] = scans
			
			return response
		
		else:	
			if r.status_code == 204:
				print("   API limit reached. Retrying in "+ str(delay) + "  seconds")				
			else:
				print("   API request error (status code:"+str(r.status_code)+"). Retrying in "+ str(delay) + " seconds")
			
			time.sleep(delay)	

	print("   Max retry reached")
	return 	{"response_code" : -1}  # max retry reached

def uploadFile(apikey, f,maxRetry,delay):
	"""
	Return: 
		response_code = 1 : upload successful
		response_code = -1 : max retry reached
	"""	

	url = 'https://www.virustotal.com/vtapi/v2/file/scan'
	data = {'apikey': apikey}
	files = {'file' : f}
	print("   Uploading File...")
	for attempt in range(maxRetry):			
		r = requests.post(url, data=data, files=files)
		if(r.status_code == 200):
			parsed_json =  json.loads(r.text)
			return {"response_code":1,"sha256":parsed_json['sha256'],"permalink":parsed_json['permalink']}
		else:	
			if r.status_code == 204:
				print("   API limit reached. Retrying in "+ str(delay) + " seconds")				
			else:
				print("   API request error (status code:"+str(r.status_code)+"). Retrying in "+ str(delay) + " seconds")			
			time.sleep(delay)

	print("   Max retry reached")
	return 	{"response_code" : -1}  # max retry reached

def main(args):	
	filenames = [args["file"]]
	excludedfiles = args["excludedfiles"]
	apikey = args["api"]
	upload = args["upload"]
	uploadonly = args["uploadonly"]
	delay = args["delay"]
	output = args["outputfile"]
	maxRetry = args["maxretry"]
	excludedfileslist = []
	
	#list filenames in directories (including subdirectories)
	if os.path.isdir(filenames[0]): filenames = [os.path.join(r,file) for r,d,f in os.walk(filenames[0]) for file in sorted(f)]
	
	#Get excluded files list
	if excludedfiles and os.path.isfile(excludedfiles):
		print("Checking for excluded list in " + excludedfiles + ". Files in the list will not be processed.")
		excludedlist = open(excludedfiles, 'r')
		for excludedfile in excludedlist.read().splitlines(): 
			excludedfileslist.append(excludedfile)
		excludedlist.close()


	isOutputExists = os.path.isfile(output)
	output_file = open(output,'a')
	output_writer = csv.writer(output_file,delimiter=',',quotechar='"',quoting=csv.QUOTE_MINIMAL)	

	#add header if output file has not been created before
	if not(isOutputExists):
		output_writer.writerow(['Progress','Filename','SHA256','Permalink','Detection','Total AV','Scans'])	
		
	
	totalFiles = len(filenames)
	for fileIdx, filename in enumerate(filenames):		
		f = open(filename,'rb')	
		fname = os.path.basename(filename)
		filehash = sha256(filename)

		print("File "+str(fileIdx+1)+"/"+str(totalFiles) + ": "+ str(fname))

		if fname in excludedfileslist:
			print("   "+ fname + " is in the excluded list and will not be processed")
			continue

		
		output_row = [str(fileIdx+1)+"/"+str(totalFiles) ,fname]

		if upload or uploadonly: 
			uploadResult = uploadFile(apikey, f,maxRetry,delay)
			if uploadResult["response_code"] == 1:
				filehash = uploadResult['sha256']
				
			else:
				output_row.append("Max upload retry reached..skipping file")
				output_writer.writerow(output_row)	
				f.close()
				continue

		if not uploadonly:
			scanResult = scanHash(apikey,filehash,maxRetry,delay)
			if scanResult["response_code"] == 1:
				output_row.append(scanResult['sha256'])
				output_row.append(scanResult['permalink'])
				output_row.append(scanResult['positives'])
				output_row.append(scanResult['total'])
				output_row.append(scanResult['scans'])
			elif scanResult["response_code"] == 0: 
				output_row.append("Hash not found in Virustotal. You may try to include -u in the argument to upload the file")
			else:
				output_row.append("Max scan retry reached..skipping file")
				
		
		output_writer.writerow(output_row)	
		f.close()
	
	output_file.close()

if __name__ == '__main__':
	version = "1.1"
	
	args = argparse.ArgumentParser()
	
	args.add_argument("-k", "--api", required=True, help="VirusTotal API Key")
	args.add_argument("-f", "--file", required=True,  help="File to be scanned")
	args.add_argument("-x", "--excludedfiles", required=False,  help="File containing list of files to be excluded (separated by newline)")
	args.add_argument("-u", "--upload", required=False, action="store_true", help="Enable uploading file and scan to Virustotal")
	args.add_argument("-U", "--uploadonly", required=False, action="store_true", help="Enable upload only to Virustotal")
	args.add_argument("-d", "--delay", required=False, default=20, type=int, help="Delay in seconds after API limit reached or scan result is not ready")
	args.add_argument("-o", "--outputfile", required=True, help="Output file in csv format. If the file already exists, hashes listed in the file will be skipped") 
	args.add_argument("-r", "--maxretry", required=False, type=int, default=100, help="Max number of request retries to Virustotal API")
	

	args = vars(args.parse_args())

	main(args)
