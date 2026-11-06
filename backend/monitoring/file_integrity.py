import socket
import subprocess
import time
from collections import defaultdict
from rysk_score import calculate_risk_score, get_local_network_info, get_public_ip_and_location
connection_tracker = defaultdict(list)
def kill_internet_connection(adapter_name="Wi-Fi"):
    try:
        cmd = f'netsh interface set interface "{adapter_name}" admin=DISABLED'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            print(f"\n[SECURITY PROTOCOL ENGAGED] Network adapter '{adapter_name}' disabled. Internet severed.")
            return True
        return False
    except Exception as e:
        print(f"[ERROR] Kill-switch failed: {e}")
        return False
def evaluate_real_threats(attacker_ip):
    current_time = time.time()
    connection_tracker[attacker_ip] = [t for t in connection_tracker[attacker_ip] if current_time - t < 10]
    connection_tracker[attacker_ip].append(current_time)

    is_port_scanning = len(connection_tracker[attacker_ip]) >= 5
    assessment = calculate_risk_score(
        ip=attacker_ip,
        location="Unknown_External" if attacker_ip != "127.0.0.1" else "Brașov",
        mac_address="AA:BB:CC:DD:EE:FF",
        concurrent_logins=6 if is_port_scanning else 1,
        file_integrity_modified=is_port_scanning
    )

    print(f"\n[!] Connection from IP: {attacker_ip} | Rapid Attempts: {len(connection_tracker[attacker_ip])}")
    print(f"Risk Assessment: {assessment}")

    if assessment["risk_level"] == "SEVERE" or is_port_scanning:
        print("[SEVERE THREAT DETECTED] Triggering automated defensive kill-switch...")
        kill_internet_connection(adapter_name="Wi-Fi")
        return True
    return False

def start_real_defense_listener(host="0.0.0.0", port=9999):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] Real-World Defense Listener active on {host}:{port}")

    while True:
        client_socket, addr = server.accept()
        attacker_ip = addr[0]

        is_severe = evaluate_real_threats(attacker_ip)
        if is_severe:
            client_socket.send(b"Access Blocked: Intrusion Detected.\n")
            client_socket.close()
            break
        else:
            client_socket.send(b"Connection OK.\n")
        client_socket.close()

if __name__ == "__main__":
    start_real_defense_listener()