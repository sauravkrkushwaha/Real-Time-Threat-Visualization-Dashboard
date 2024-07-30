import os
import time
import sys

# Define log file paths for different firewalls (add more as needed)
FIREWALL_LOG_FILES = {
    "Windows Firewall": r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log",
    "Cisco ASA": r"/var/log/cisco_asa.log",  # Example path for Cisco ASA logs
    "pfSense": r"/var/log/filter.log",       # Example path for pfSense logs
    # Add other firewalls and their log paths here
}

def monitor_log_file(log_file_path):
    """Monitor the log file and process new entries in real-time."""
    try:
        with open(log_file_path, 'r') as log_file:
            # Move to the end of the file
            log_file.seek(0, os.SEEK_END)
            
            while True:
                line = log_file.readline()
                if not line:
                    time.sleep(1)  # Sleep briefly and wait for new lines
                    continue
                
                process_log_entry(line)
    except FileNotFoundError:
        print(f"Log file not found: {log_file_path}")
    except PermissionError:
        print(f"Permission denied: {log_file_path}")
    except Exception as e:
        print(f"Error monitoring log file: {e}")

def process_log_entry(log_entry):
    """Process a single log entry."""
    # Add your log processing logic here
    print(f"New log entry: {log_entry.strip()}")

def main():
    # Check if running as administrator
    if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
        print("This script needs to be run with administrative privileges.")
        sys.exit(1)
    
    # Ask user to select the firewall type
    print("Available firewall logs to monitor:")
    for i, firewall in enumerate(FIREWALL_LOG_FILES.keys(), start=1):
        print(f"{i}. {firewall}")
    
    try:
        choice = int(input("Select the firewall (by number): ")) - 1
        selected_firewall = list(FIREWALL_LOG_FILES.keys())[choice]
        log_file_path = FIREWALL_LOG_FILES[selected_firewall]
        
        print(f"Monitoring log file for {selected_firewall}: {log_file_path}")
        monitor_log_file(log_file_path)
    except (ValueError, IndexError):
        print("Invalid choice. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()
