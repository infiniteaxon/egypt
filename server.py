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
                received_data = b''
                while len(received_data) < file_size:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break  # Connection closed
                    received_data += chunk

                server_file_hash = hash_file(received_data)
                if server_file_hash == client_file_hash:
                    with open(file_path, 'wb') as f:
                        f.write(received_data)
                    conn.sendall(b"File uploaded successfully.")
                else:
                    conn.sendall(b"File hash mismatch, upload failed.")

           elif command == 'DOWNLOAD':
                file_name = args[0]
                file_path = os.path.join(STORAGE_DIR, file_name)
            
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
            
                    server_file_hash = hash_file(file_data)
                    file_size = len(file_data)
                    # Make sure to send the encrypted file size
                    conn.sendall(f"{file_size} {server_file_hash}".encode('utf-8'))
            
                    # Then send the file content
                    conn.sendall(file_data)

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
