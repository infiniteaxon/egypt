import socket
import os
import threading
import hashlib
import ssl
import time

# Server settings
HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 32603       # Port to listen on (non-privileged ports are > 1023)

# SSL Stuff
CERTFILE = 'server.crt'
KEYFILE = 'server.key'

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
                subdirectory, file_name, file_size, client_file_hash = args
                file_size = int(file_size)
                # Join paths can create if not there
                directory_path = os.path.join(STORAGE_DIR, subdirectory)
                os.makedirs(directory_path, exist_ok=True)
                file_path = os.path.join(directory_path, file_name)
                file_exists = os.path.exists(file_path)
            
                # Handle upload data
                received_data = b''
                print(f"[*] Upload from {addr}")
                # Set data size expectation
                while len(received_data) < file_size:
                    chunk = conn.recv(min(4096, file_size - len(received_data)))
                    if not chunk:
                        break
                    received_data += chunk
                # Check hash for integrity
                server_file_hash = hash_file(received_data)
                if server_file_hash == client_file_hash:
                    with open(file_path, 'wb') as f:
                        f.write(received_data)
                    # Send responses
                    if not file_exists:
                        conn.sendall(b"[*] New file created and uploaded successfully.")
                    else:
                        conn.sendall(b"[*] File overwritten successfully.")
                else:
                    conn.sendall(b"[!] File hash mismatch, upload failed.")

            elif command == 'DOWNLOAD':
                file_name = args[0]
                file_path = os.path.join(STORAGE_DIR, file_name)
                print(f"[*] Download to {addr}")

                # Get download data
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

            elif command == 'LIST':
                # List the file details with CSV
                list_results = list_files(STORAGE_DIR)
                conn.sendall(list_results.encode('utf-8'))

            else:
                conn.sendall(b"[!] Invalid command.")

    except Exception as e:
        print(f"[!] Error handling client {addr}: {e}")
    finally:
        print(f"[-] Disconnection from {addr}")
        conn.close()

def list_files(startpath):
    files_found = ["Filename,Size (bytes),Created"]
    for root, dirs, files in os.walk(startpath):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, startpath)
            file_size = os.path.getsize(file_path)
            creation_date = time.ctime(os.path.getctime(file_path))
            files_found.append(f"\"{relative_path}\",{file_size},\"{creation_date}\"")
    return "\n".join(files_found) if len(files_found) > 1 else "No files found in storage."

def main():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(CERTFILE, KEYFILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"[*] Secure server listening on {HOST}:{PORT}")
        while True:
            conn, addr = server_socket.accept()
            sconn = context.wrap_socket(conn, server_side=True)
            thread = threading.Thread(target=handle_client, args=(sconn, addr), daemon=True)
            thread.start()

if __name__ == "__main__":
    main()
