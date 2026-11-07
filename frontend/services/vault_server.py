
import socket
import hashlib
from pathlib import Path
from datetime import datetime

HOST = "0.0.0.0"
PORT = 5050

PROJECT_DIR = Path(__file__).resolve().parent.parent
VAULT_DIR = PROJECT_DIR / "backups"

VAULT_DIR.mkdir(parents=True, exist_ok=True)


def calculate_sha256(data):
    return hashlib.sha256(data).hexdigest()


def receive_exactly(connection, size):
    """Primește exact numărul de bytes solicitat."""
    chunks = []
    received = 0

    while received < size:
        chunk = connection.recv(min(4096, size - received))

        if not chunk:
            raise ConnectionError("Connection interrupted.")

        chunks.append(chunk)
        received += len(chunk)

    return b"".join(chunks)


def handle_client(connection, address):
    print(f"\n[CONNECTION] Client connected: {address}")

    try:
        connection.settimeout(15)

        header = bytearray()

        while not header.endswith(b"\n"):
            chunk = connection.recv(1)

            if not chunk:
                raise ConnectionError("Header incomplete.")

            header.extend(chunk)

            if len(header) > 256:
                raise ValueError("Invalid header.")

        size_text, expected_hash = (
            header.decode("ascii").strip().split(":")
        )

        file_size = int(size_text)

        if file_size < 0 or file_size > 10 * 1024 * 1024:
            raise ValueError("File size not allowed.")

        payload = receive_exactly(connection, file_size)

        received_hash = calculate_sha256(payload)

        if received_hash != expected_hash:
            connection.sendall(b"ERROR_HASH\n")
            print("[ERROR] SHA-256 verification failed.")
            return

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S_%f"
        )

        backup_file = VAULT_DIR / f"vault_backup_{timestamp}.bin"

        with open(backup_file, "xb") as file:
            file.write(payload)
            file.flush()

        saved_data = backup_file.read_bytes()

        if calculate_sha256(saved_data) != expected_hash:
            backup_file.unlink()
            connection.sendall(b"ERROR_STORAGE\n")
            print("[ERROR] Saved backup verification failed.")
            return

        connection.sendall(b"ACK_STORED\n")

        print(f"[SUCCESS] Backup saved: {backup_file.name}")
        print(f"[SHA-256] {received_hash}")

    except Exception as error:
        print(f"[ERROR] {error}")

        try:
            connection.sendall(b"ERROR_TRANSFER\n")
        except OSError:
            pass

    finally:
        connection.close()
        print("[CONNECTION] Client disconnected.")


def start_vault_server():
    print("=" * 45)
    print("       OBSIDIAN SECURE VAULT")
    print("=" * 45)
    print(f"[INFO] Vault directory: {VAULT_DIR}")
    print(f"[INFO] Listening on port: {PORT}")
    print("[INFO] Waiting for backup connections...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        server.bind((HOST, PORT))
        server.listen(5)

        while True:
            connection, address = server.accept()
            handle_client(connection, address)


if __name__ == "__main__":
    start_vault_server()
