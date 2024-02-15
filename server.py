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

def handle_client(conn, addr):
    print(f"Connected by {addr}")
    try:
        while True:
            # Receive command from the client
            data = conn.recv(1024).decode('utf-8')
            if not data:
                break  # No data means the client has closed the connection

            command, *args = data.split()

            if command == 'UPLOAD':
                file_name, file_size, client_file_hash = args
                file_size = int(file_size)
                file_path = os.path.join(STORAGE_DIR, file_name)

                # Receive the file
                with open(file_path, 'wb') as f:
                    bytes_read = 0
                    while bytes_read < file_size:
                        bytes_to_read = min(4096, file_size - bytes_read)
                        chunk = conn.recv(bytes_to_read)
                        if not chunk:
                            break  # Connection closed
                        f.write(chunk)
                        bytes_read += len(chunk)

                # Calculate and store the hash of the received file
                server_file_hash = hashlib.sha256()
                with open(file_path, 'rb') as file:
                    for byte_block in iter(lambda: file.read(4096), b""):
                        server_file_hash.update(byte_block)
                server_file_hash = server_file_hash.hexdigest()

                if server_file_hash == client_file_hash:
                    conn.sendall(b"File uploaded successfully.")
                else:
                    os.remove(file_path)  # Remove the file as the hash doesn't match
                    conn.sendall(b"File hash mismatch, upload failed.")

            elif command == 'DOWNLOAD':
                file_name = args[0]
                file_path = os.path.join(STORAGE_DIR, file_name)

                if os.path.exists(file_path):
                    # Calculate the hash of the file to be sent
                    server_file_hash = hashlib.sha256()
                    with open(file_path, 'rb') as file:
                        for byte_block in iter(lambda: file.read(4096), b""):
                            server_file_hash.update(byte_block)
                    server_file_hash = server_file_hash.hexdigest()

                    # Send file size and hash first
                    file_size = os.path.getsize(file_path)
                    conn.sendall(f"{file_size} {server_file_hash}".encode('utf-8'))

                    # Then send the file content
                    with open(file_path, 'rb') as f:
                        while (chunk := f.read(4096)):
                            conn.sendall(chunk)
                else:
                    conn.sendall(b"File not found.")

            else:
                conn.sendall(b"Invalid command.")

    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        print(f"Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    main()
