import time
from collections import defaultdict

connection_tracker = defaultdict(list)

def detect_port_scan(attacker_ip, threshold_attempts=5, window_seconds=10):
    current_time = time.time()

    connection_tracker[attacker_ip] = [
        t for t in connection_tracker[attacker_ip] if current_time - t < window_seconds
    ]

    connection_tracker[attacker_ip].append(current_time)

    if len(connection_tracker[attacker_ip]) >= threshold_attempts:
        return True
    return False