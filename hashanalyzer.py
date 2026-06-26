import hashlib
import sys
import os
import requests


# input api key
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def calculate_hashes(filepath):
    """
    Calculate MD5, SHA-1, and SHA-256 hashes of a file.
    
    Args:
        filepath (str): Path to file to hash
    
    Returns:
        dict: Hashes {md5, sha1, sha256}
    """

    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    try :
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
            
        return {
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }

    except FileNotFoundError:
        print(f"Error file not found!!: {filepath}")
        sys.exit(1)
    
    except PermissionError:
        print(f"Error: Permission denied reading {filepath}")
        sys.exit(1)

    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

def get_file_size(filepath):
    # human readable file size
    size = os.path.getsize(filepath)
    for unit in ['B','KB', 'MB','GB', 'TB']:
        if size< 1024:
            return f"{size:.2f} {unit}"
        size/=1024
    return f"{size:.2f} PB"

def query_virustotal(file_hash):

    if not VIRUSTOTAL_API_KEY:
        print("Error: VIRUSTOTAL_API_KEY environment variable not set")
        print("Set it with: export VIRUSTOTAL_API_KEY = 'your_api_key'")
        return None

    # virustotal API endpoint for file hash lookup
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey" : VIRUSTOTAL_API_KEY
    }

    try:
        print(f"\n[*] Querying virustotal for hash : {file_hash[:16]}...")

        #make API requests
        response = requests.get(url, headers= headers, timeout = 10)

        #check response status
        if response.status_code == 200:
            #hash found in database
            data = response.json()
            return data 
        
        elif response.status_code == 404:
            #hash not found (not detected as malware)
            return {"not_found": True}
        
        elif response.status_code == 401:
            print("Error: Invalid API key")
            return None

        elif response.status_code == 429:
            print("Error: Rate limit exceeded (4 requests/minute)")
            print("Wait a minute and try again")
            return None
        
        else:
            print(f"Error: API returned status {response.status_code}")
            print(response.text)
            return None

    except requests.exceptions.Timeout:
        print("Error: Requests timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("Error: Connection failed (check internet)")
        return None
    except Exception as e:
        print(f"Error querying VirusTotal: {e}")
        return None
    
def parse_virustotal_results(data):

    if not data:
        return None
    if data.get("not_found"):
        return {
            "status": "CLEAN",
            "message": "Not detected in VirusTotal database",
            "detections": 0
        }

    try :
        # extract last analysis stats
        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)

        total_scans = malicious + suspicious + undetected + stats.get("harmless", 0)

        #determined status
        if malicious > 0:
            status = "MALWARE"
        elif suspicious > 0 :
            status = "SUSPICIOUS"
        else:
            status ="CLEAN"
        
        return {
            "status": status,
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "total_scans": total_scans 
        }
    except KeyError:
        return None


if __name__ == "__main__":
    if len(sys.argv)<2:
        print("Usage: python hashanalyzer.py <filepath>")
        print("Example: python hashanalyzer.py document.pdf")
        sys.exit(1)
    
    filepath = sys.argv[1]

    #verify file exists
    if not os.path.isfile(filepath):
        print(f"Error: Not a file: {filepath}")
        sys.exit(1)

    hashes = calculate_hashes(filepath)
    file_size = get_file_size(filepath)

    # display results
    print(f"\n{'-'*70}")
    print("File Hash Analyzer")
    print(f"\n{'-'*70}")
    print(f"File: {filepath}")
    print(f"Size: {file_size}")
    print(f"{'-'*70}\n")

    print(f"MD5:        {hashes['md5']}")
    print(f"SHA-1:      {hashes['sha1']}")
    print(f"SHA-256:    {hashes['sha256']}")
    
    # query virustotal for SHA-256 (most secure)
    vt_data = query_virustotal(hashes['sha256'])
    results = parse_virustotal_results(vt_data)

    if results:
        print(f"{'='*70}")
        print(f"VirusTotal Results")
        print(f"{'='*70}")
        print(f"Status: {results['status']}")
        
        if results['status'] == "MALWARE":
            print(f"!!!WARNING: File detected as MALWARE!")
            print(f"Malicious detections: {results['malicious']}/{results['total_scans']}")
        elif results['status'] == "SUSPICIOUS":
            print(f"!SUSPICIOUS: Some engines flagged this file")
            print(f"Suspicious detections: {results['suspicious']}/{results['total_scans']}")
        else:
            print(f"<CLEAN: Not detected as malware>")
        
        print()
    else:
        print("!!Could not query VirusTotal")
        print("Set API key: export VIRUSTOTAL_API_KEY='your_key'")

