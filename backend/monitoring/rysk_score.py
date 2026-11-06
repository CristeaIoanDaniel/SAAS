import socket
import urllib.request
import json
import uuid

DEFAULT_IP = "0.0.0.0"
DEFAULT_LOCATION = "Braila"

def get_local_network_info():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"
    mac_num = uuid.getnode()
    mac_address = ':'.join(['{:02x}'.format((mac_num >> elements) & 0xff) for elements in range(5,-1,-1)])

    return local_ip, mac_address

def get_public_ip_and_location():
    try:
        url = "https://ipinfo.io/json"
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode())
            return data.get("ip", DEFAULT_IP), data.get("city", DEFAULT_LOCATION)
    except Exception:
        return DEFAULT_IP, DEFAULT_LOCATION

def calculate_risk_score(ip, location, mac_address, concurrent_logins=1, file_integrity_modified=False):
    score = 0
    factors = []
    if ip in ["0.0.0.0", "0 0 0 0", "127.0.0.1"]:
        score += 35
        factors.append(f"Default/Loopback IP detected: {ip}")
    elif ip.startswith("192.168.") or ip.startswith("10."):
        score += 5
        factors.append(f"Internal Network IP: {ip}")
    else:
        score += 25
        factors.append(f"External/Public IP: {ip}")
    if location.lower() == "braila":
        score += 10
        factors.append(f"Baseline Location: {location}")
    else:
        score += 35
        factors.append(f"Unrecognized/Anomaly Location: {location}")
    if not mac_address or mac_address in ["00:00:00:00:00:00", "0"]:
        score += 20
        factors.append("Missing or Null MAC Address")
    else:
        score += 5
        factors.append(f"MAC Address Registered: {mac_address}")
    if concurrent_logins > 3:
        score += 30
        factors.append(f"High Concurrent Logins: {concurrent_logins}")
    elif concurrent_logins > 1:
        score += 15
        factors.append(f"Multiple Concurrent Logins: {concurrent_logins}")
    else:
        score += 0
        factors.append("Single Login Session (Normal)")

    # 5. File Integrity Evaluation
    if file_integrity_modified:
        score += 40
        factors.append("File Integrity Breach: Unauthorized file modifications detected")
    else:
        score += 0
        factors.append("File Integrity Intact")

    # Risk Level Classification
    if score >= 75:
        risk_level = "SEVERE"
    elif score >= 45:
        risk_level = "THREAT"
    elif score >= 20:
        risk_level = "WARNING"
    else:
        risk_level = "NORMAL"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "trigger_factors": factors
    }

if __name__ == "__main__":
    print("--- Scanning Local Machine Network State ---")
    live_ip, live_mac = get_local_network_info()
    _, live_location = get_public_ip_and_location()

    print(f"Detected IP: {live_ip}")
    print(f"Detected Location: {live_location}")
    print(f"Detected MAC Address: {live_mac}\n")

    print("--- Running Live Risk Assessment ---")
    live_test = calculate_risk_score(
        ip=live_ip,
        location=live_location,
        mac_address=live_mac,
        concurrent_logins=1,
        file_integrity_modified=False
    )
    print(live_test)