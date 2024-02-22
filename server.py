import socket
import os
import threading
import hashlib

# Server settings
HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 32603       # Port to listen on (non-privileged ports are > 1023)

# Directory to store received files
STORAGE_DIR = 'egypt_server_storage'
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

def hash_file(file_data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_data)
    return sha256_hash.hexdigest()

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    try:
        while True:
            data = conn.recv(1024).decode('utf-8')
            if not data:
                break

            command, *args = data.split()

            if command == 'UPLOAD':
                file_name, file_size, client_file_hash = args
                file_size = int(file_size)
                file_path = os.path.join(STORAGE_DIR, file_name)
                received_data = b''
                print(f"[*] Upload from {addr}")
                while len(received_data) < file_size:
                    chunk = conn.recv(min(4096, file_size - len(received_data)))
                    if not chunk:
                        break
                    received_data += chunk

                server_file_hash = hash_file(received_data)
                if server_file_hash == client_file_hash:
                    with open(file_path, 'wb') as f:
                        f.write(received_data)
                    conn.sendall(b"[*] File uploaded successfully.")
                else:
                    conn.sendall(b"[!] File hash mismatch, upload failed.")

            elif command == 'DOWNLOAD':
                file_name = args[0]
                file_path = os.path.join(STORAGE_DIR, file_name)
                print(f"[*] Download to {addr}")

                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        file_data = f.read()

                    server_file_hash = hash_file(file_data)
                    file_size = len(file_data)
                    conn.sendall(f"{file_size} {server_file_hash}".encode('utf-8'))

                    # Send the file content in chunks
                    for i in range(0, len(file_data), 4096):
                        conn.sendall(file_data[i:i+4096])
                else:
                    conn.sendall(b"[!] File not found.")

            else:
                conn.sendall(b"[!] Invalid command.")

    except Exception as e:
        print(f"[!] Error handling client {addr}: {e}")
    finally:
        print(f"[-] Disconnection from {addr}")
        conn.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    main()
