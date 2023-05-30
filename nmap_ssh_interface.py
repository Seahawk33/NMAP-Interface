import subprocess

#This is the scan options. can be combined by placing space between choices
scan_options = {
    '1': ('-sS', 'TCP SYN scan - Stealthy scan that attempts to determine open ports by sending SYN packets and anal>    '2': ('-sT', 'TCP connect scan - Establishes a full TCP connection with the target ports to determine if they ar>    '3': ('-sA', 'TCP ACK scan - Identifies whether ports are filtered by sending ACK packets and analyzing the resp>    '4': ('-sU', 'UDP scan - Determines which UDP ports are open on the target system.'),
    '5': ('-sV', 'Service version detection - Attempts to determine the version of the running services on the targe>    '6': ('-sC', 'Script scan - Executes default or user-defined scripts to gather additional information about targ>}

#places box around scan choices
def display_scan_options():
    print("+" + "-" * 128 + "+")
    print("|" + " " * 128 + "|")
    print("|" + " " * 58 + "Scan Options" + " " * 58 + "|")
    print("|" + " " * 128 + "|")
    for option, (scan_type, description) in scan_options.items():
        print("| \033[1m" + option + ". " + scan_type + ":\033[0m")
        print("|   " + description)
        print("|" + " " * 128 + "|")
    print("+" + "-" * 128 + "+")

#runs nmap on target(s)
def run_nmap_scan(targets, scan_types):
    try:
        command = f"nmap {' '.join(scan_types)} {targets}"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        if process.returncode == 0:
            print("\n\033[1mNmap scan completed successfully. Results:\033[0m")
            print(output.decode())
        else:
            print("\n\033[1mAn error occurred while running the Nmap scan:\033[0m")
            print(f"Error message: {error.decode()}")
        print("-" * 40)
    except Exception as e:
        print(f"\n\033[1mAn error occurred:\033[0m {str(e)}")

#differentiates between range, singular, or multiple IPs
def parse_ip_range(ip_range):
    start, end = ip_range.split('-')
    start_parts = start.split('.')
    end_parts = end.split('.')

    if len(start_parts) != 4 or len(end_parts) != 4:
        return []

    try:
        start_parts = [int(part) for part in start_parts]
        end_parts = [int(part) for part in end_parts]

        ips = []
        for i in range(start_parts[3], end_parts[3] + 1):
            ip = f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}"
            ips.append(ip)
	  return ips
    except ValueError:
        return []

#input functions
def main():
    display_scan_options()
    targets = input("\nEnter the IP address(es) to scan (separated by spaces or '-'): ")
    scan_choices = input("Enter the scan types to perform (separated by spaces): ").split()

    scan_types = []
    for choice in scan_choices:
        if choice in scan_options:
            scan_type, _ = scan_options[choice]
            scan_types.append(scan_type)

    if targets and scan_types:
        print("\nSelected Scan Types:")
        for scan_type in scan_types:
            print(f"\033[1m{scan_type}\033[0m")
        print()

        ip_range = targets.strip()
        if '-' in ip_range:
            ips = parse_ip_range(ip_range)
            if ips:
                targets = ' '.join(ips)
                run_nmap_scan(targets, scan_types)
            else:
                print("Invalid IP range. Please provide a valid range (e.g., 10.10.0.160-10.10.0.164).")
        else:
            run_nmap_scan(targets, scan_types)
    else:
        print("Invalid input.")

if __name__ == "__main__":
    main()
