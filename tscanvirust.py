import hashlib
import requests
import os
import time

def analyze_file_virustotal(file_path, api_key):
    """
    Analyzes a file for viruses using the VirusTotal API.

    Args:
        file_path (str): The path to the file to analyze.
        api_key (str): Your VirusTotal API key.

    Returns:
        dict or None: A dictionary containing the VirusTotal analysis report if successful,
                     None otherwise.
    """
    if not os.path.exists(file_path):
        print(f"Error: File not found at '{file_path}'")
        return None

    file_size = os.path.getsize(file_path)
    if file_size > 33554432:  # 32 MB limit for free API
        print("Error: File size exceeds the limit for the free VirusTotal API (32 MB).")
        print("Consider using the API to scan by hash or upgrade your VirusTotal account.")
        return None

    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
        file_hash = hashlib.sha256(file_content).hexdigest()

        url = "https://www.virustotal.com/api/v3/files"
        headers = {"x-apikey": api_key}
        files = {"file": (os.path.basename(file_path), file_content)}

        print(f"Uploading '{os.path.basename(file_path)}' to VirusTotal...")
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()  # Raise an exception for bad status codes
        analysis_id = response.json().get("data", {}).get("id")

        if analysis_id:
            print(f"File uploaded successfully. Analysis ID: {analysis_id}")
            return get_analysis_report(analysis_id, api_key)
        else:
            print("Error: Failed to retrieve analysis ID.")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Error during API request: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def get_analysis_report(analysis_id, api_key):
    """
    Retrieves the VirusTotal analysis report using the analysis ID.

    Args:
        analysis_id (str): The ID of the analysis to retrieve.
        api_key (str): Your VirusTotal API key.

    Returns:
        dict or None: A dictionary containing the VirusTotal analysis report if successful,
                     None otherwise.
    """
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": api_key}

    print("Waiting for analysis to complete...")
    while True:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        report = response.json().get("data", {}).get("attributes")
        if report:
            status = report.get("status")
            if status == "completed":
                print("Analysis completed.")
                return report.get("results")
            elif status == "queued" or status == "processing":
                print("Analysis still in progress. Waiting 10 seconds...")
                time.sleep(10)
            else:
                print(f"Analysis status: {status}")
                return None
        else:
            print("Error: Could not retrieve analysis report.")
            return None

def print_analysis_results(results):
    """
    Prints the VirusTotal analysis results in a user-friendly format.

    Args:
        results (dict): The dictionary containing the analysis results.
    """
    if results:
        print("\n--- VirusTotal Analysis Results ---")
        detected_by = 0
        total_scanners = len(results)
        for engine, result in results.items():
            if result.get("detected"):
                detected_by += 1
                print(f"- {engine}: Detected ({result.get('result')})")
        print(f"\n{detected_by} out of {total_scanners} scanners reported this file as malicious.")
        if detected_by > 0:
            print("It is recommended to treat this file with caution.")
        else:
            print("No significant threats detected by the scanners.")
    else:
        print("No analysis results available.")

if __name__ == "__main__":
    file_to_scan = input("Enter the path to the file you want to scan: ")
    api_key = input("Enter your VirusTotal API key: ")

    if not api_key:
        print("Error: VirusTotal API key is required.")
    else:
        analysis_report = analyze_file_virustotal(file_to_scan, api_key)
        if analysis_report:
            print_analysis_results(analysis_report)