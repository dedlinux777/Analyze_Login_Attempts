import win32evtlog
import datetime

def analyze_login_attempts():
    # Open the Security event log
    hand = win32evtlog.OpenEventLog(None, "Security")
    
    # Go to the end of the log
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    events = win32evtlog.ReadEventLog(hand, flags, 0)
    
    # Dictionary to store failed login attempts
    failed_attempts = {}
    
    # Iterate through the events
    while events:
        for event in events:
            if event.EventID == 4625:  # Failed logon event ID
                ip_address = event.StringInserts[18]
                if ip_address not in failed_attempts:
                    failed_attempts[ip_address] = 1
                else:
                    failed_attempts[ip_address] += 1
        
        # Read the next group of events
        events = win32evtlog.ReadEventLog(hand, flags, 0)
    
    # Close event log
    win32evtlog.CloseEventLog(hand)
    
    # Print warning for multiple failed login attempts
    for ip, attempts in failed_attempts.items():
        if attempts > 3:
            print(f"Warning: Multiple failed login attempts detected from IP address {ip}")

analyze_login_attempts()
