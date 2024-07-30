import win32evtlog  # Import the win32evtlog module from pywin32
import sys
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def count_logs():
    log_types = ["Application", "Security", "System", "Setup", "ForwardedEvents"]
    log_counts = {}
    
    for log_type in log_types:
        try:
            log_handle = win32evtlog.OpenEventLog(None, log_type)
            log_count = win32evtlog.GetNumberOfEventLogRecords(log_handle)
            log_counts[log_type] = log_count
            win32evtlog.CloseEventLog(log_handle)
        except Exception as e:
            log_counts[log_type] = f"Error: {e}"

    print("Total number of logs:")
    for log_type, count in log_counts.items():
        print(f"{log_type} Log: {count}")

    if not is_admin():
        print("\nWarning: You do not have administrative privileges.")
        print("Some logs, such as Security and possibly System logs, may not be fully accessible.")
        print("For complete access, consider running the script as an administrator.")

if __name__ == "__main__":
    count_logs()
