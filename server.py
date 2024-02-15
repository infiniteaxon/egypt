import socket
import os
from cryptography.fernet import Fernet
import threading

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
                file_name = args[0]
                file_size = int(args[1])
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

                conn.sendall(b"File uploaded successfully.")

            elif command == 'DOWNLOAD':
                file_name = args[0]
                file_path = os.path.join(STORAGE_DIR, file_name)

                if os.path.exists(file_path):
                    # Send file size first
                    file_size = os.path.getsize(file_path)
                    conn.sendall(f"{file_size}".encode('utf-8'))

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
