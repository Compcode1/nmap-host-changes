import nmap
import time
import datetime

# Define scan settings
target_network = "192.168.1.0/24"
scan_interval = 300  # 5 minutes in seconds
scan_log = "nmap_scan_log.txt"

# Initialize Nmap scanner
nm = nmap.PortScanner()

# Function to perform an Nmap scan
def run_scan(scan_number):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scan_label = "Baseline Scan" if scan_number == 1 else f"Scan {scan_number}"
    print(f"\n🔍 {scan_label} running at {timestamp}...\n")

    nm.scan(hosts=target_network, arguments="-sV -T4")  # Service version detection scan
    scan_results = {}

    # Process scan results
    for host in nm.all_hosts():
        scan_results[host] = {}
        for proto in nm[host].all_protocols():
            scan_results[host][proto] = {port: nm[host][proto][port]['name'] for port in nm[host][proto].keys()}

    return timestamp, scan_results, scan_label

# Function to compare scans and detect changes
def compare_scans(previous_scan, current_scan):
    changes = []
    prev_hosts = set(previous_scan.keys())
    curr_hosts = set(current_scan.keys())

    # Detect new or missing hosts
    new_hosts = curr_hosts - prev_hosts
    removed_hosts = prev_hosts - curr_hosts

    for host in new_hosts:
        changes.append(f"🆕 New Host Detected: {host}")

    for host in removed_hosts:
        changes.append(f"❌ Host Removed: {host}")

    # Compare services and ports per host
    for host in curr_hosts & prev_hosts:
        prev_ports = previous_scan[host].get("tcp", {})
        curr_ports = current_scan[host].get("tcp", {})

        new_ports = set(curr_ports.keys()) - set(prev_ports.keys())
        closed_ports = set(prev_ports.keys()) - set(curr_ports.keys())

        if new_ports:
            changes.append(f"🔺 {host}: New Open Ports -> {', '.join(map(str, new_ports))}")
        if closed_ports:
            changes.append(f"🔻 {host}: Closed Ports -> {', '.join(map(str, closed_ports))}")

    return changes

# Main loop to run scans every 5 minutes
previous_scan = {}
scan_count = 1  # Track the scan number

while scan_count <= 6:  # Adjust if more scans are needed
    timestamp, current_scan, scan_label = run_scan(scan_count)

    if previous_scan:
        detected_changes = compare_scans(previous_scan, current_scan)
        
        if detected_changes:
            with open(scan_log, "a") as log_file:
                log_file.write(f"\n📌 {scan_label} at {timestamp}\n")
                log_file.write("=" * 40 + "\n")
                log_file.writelines(f"{change}\n" for change in detected_changes)
            
            print("\n🔍 Changes Detected:")
            for change in detected_changes:
                print(change)
            print("\n✅ Changes logged in", scan_log)
        else:
            print("\n✅ No changes detected.")

    # Store current scan for next iteration
    previous_scan = current_scan

    if scan_count < 6:
        next_scan_time = datetime.datetime.now() + datetime.timedelta(seconds=scan_interval)
        print(f"\n⏳ Waiting {scan_interval // 60} minutes for the next scan... (Next scan at {next_scan_time.strftime('%Y-%m-%d %H:%M:%S')})")
        time.sleep(scan_interval)

    scan_count += 1

print("\n✅ All scheduled scans completed.")