import sys
import hashlib
import requests
from time import sleep

API_KEY = ''


# Calculates the hash for a given file
def hash_file(filename):
    hasher = hashlib.md5()
    with open(filename, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)

    return hasher.hexdigest()


# Performs a hash lookup against OPSWAT, returning True if successful
def hash_lookup(hash):
    url = 'https://api.metadefender.com/v2/hash/' + hash
    data = { 'apikey' : API_KEY }
    try:
        response = requests.get(url, headers = data)
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(1)

    # If file_id found, then we know this file has been uploaded before, and we will print.
    # We put a try and except statement, so the function returns False when it can't find the
    # right parameters to print in "print_results"
    try:
        print_results(response)
        return True
    except:
        return False


# Print out scan results in a clean format
def print_results(response):
    print("overall_status: " + str(response.json()['scan_results']['scan_all_result_a']))
    print("")
    all_scans = response.json()['scan_results']['scan_details']

    for scan, results in all_scans.items():
        # If threat found string is empty, we will say it is clean
        threat = str(results['threat_found'])
        if not threat: threat = 'Clean'

        print("engine: " + scan)
        print("threat found: " + threat)
        print("scan_result: " + str(results['scan_result_i']))
        print("def_time: " + str(results['def_time']))
        print("")


# Uploads file to OPSWAT and returns data id
def upload_file(filename):
    url = 'https://api.metadefender.com/v2/file'
    files = {'file': open(filename, 'rb')}
    data = { 'apikey' : API_KEY }
    try:
        r = requests.post(url, files=files, headers= data)
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(1)
    return r.json()['data_id']


# Retrieves scan results using data id
def retrieve_results(data_id):
    url = 'https://api.metadefender.com/v2/file/' + data_id
    data = { 'apikey' : API_KEY }
    try:
        response = requests.get(url, headers = data)
    except requests.exceptions.RequestException as e:
        print(e)
        sys.exit(1)
    return response


# Main logic for program
if len(sys.argv) == 1:
    print("No command entered.")

elif sys.argv[1] == 'upload_file':
    filename = sys.argv[2]
    hash = hash_file(filename)
    print("filename: " + filename)

    # First, we check if the file has been previously uploaded through hash
    # If not, we will upload it and continuously retrieve results through data id
    if not hash_lookup(hash):
        print("Uploading file...")
        data_id = upload_file(filename)
        results = retrieve_results(data_id).json()['scan_results']

        # We will constantly check the system to see the progress of the scan. We will give a 10 second sleep leeway to
        # avoid over-pinging the system
        while results['progress_percentage'] != int(100):
            print("Scanning at " + str(results['progress_percentage']) + "%...")
            sleep(10)

            try:
                response = retrieve_results(data_id)
            except requests.exceptions.RequestException as e:
                print(e)
                sys.exit(1)
            results = response.json()['scan_results']

        # Once we know it is done scanning, we will print the scan results
        print("Scanning finished!")
        print("")
        print_results(response)

else:
    print("Please enter a valid command! Ex:")
    print("upload_file filename.txt")


