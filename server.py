import socket
import os
import threading
import hashlib
import ssl
import time
import logging

# Server settings
HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 32603       # Port to listen on (non-privileged ports are > 1023)

# SSL Stuff
CERTFILE = 'server.crt'
KEYFILE = 'server.key'

# User/Password Dictionary
creds = {"axon": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"}

# Directory to store received files
STORAGE_DIR = 'egypt_server_storage'
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Create handlers for writing to file and logging to console
file_handler = logging.FileHandler('server.log')
file_handler.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# Format logs
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)



def hash_file(file_data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_data)
    return sha256_hash.hexdigest()

def handle_client(conn, addr):
    logger.info(f"[+] Connection from {addr}")
    
    if not login(conn, addr):
        conn.close()
        return

    try:
        while True:
            data = conn.recv(1024).decode('utf-8')
            if not data:
                break

            command, *args = data.split()

            if command == 'UPLOAD':
                subdirectory, file_name, file_size, client_file_hash = args
                file_size = int(file_size)  # Ensure file_size is an integer
                subdirectory_path = os.path.normpath(subdirectory)
                file_path = os.path.join(STORAGE_DIR, subdirectory_path, file_name)

                # Validate directory and create if necessary
                if ".." in subdirectory_path.split(os.sep) or not subdirectory_path.startswith('egypt_server_storage'):
                    conn.sendall(b"[!] Restricted directory submitted, upload failed.")
                    logger.warning(f"[!] Restricted directory '{subdirectory_path}' submitted from {user}@{addr}.")
                else:
                    directory_path = os.path.join(STORAGE_DIR, subdirectory_path)
            
                # Check if the real path after normalization is within the allowed STORAGE_DIR
                if not os.path.realpath(directory_path).startswith(os.path.realpath(STORAGE_DIR)):
                    conn.sendall(b"[!] Invalid directory path, upload failed.")
                    logger.error(f"[!] Invalid directory '{directory_path}' submitted from {user}@{addr}.")
                else:
                    # Create the directory if it doesn't exist
                    os.makedirs(directory_path, exist_ok=True) 
            
                received_data = b''
                received_size = 0

                while received_size < file_size:
                    chunk = conn.recv(min(4096, file_size - received_size))
                    if not chunk:
                        break
                    received_data += chunk
                    received_size += len(chunk)

                # Check hash for integrity
                server_file_hash = hash_file(received_data)
                if server_file_hash == client_file_hash:
                    with open(file_path, 'wb') as f:
                        f.write(received_data)
                    # Send responses
                    file_exists = os.path.exists(file_path)
                    if not file_exists:
                        conn.sendall(b"[*] New file created and uploaded successfully.")
                        logger.info(f"[*] {file_path} created and uploaded successfully from {username}@{addr}")
                    else:
                        conn.sendall(b"[*] File overwritten successfully.")
                        logger.info(f"[*] {file_path} overwritten successfully by {username}@{addr}")

                else:
                    conn.sendall(b"[!] File hash mismatch, upload failed.")
                    logger.warning(f"[!] {file_path} hash mismatch from {username}@{addr}")

            elif command == 'DOWNLOAD':
                
                file_name = args[0]
                file_path = os.path.join(STORAGE_DIR, file_name)
                
                # Input validation
                if ".." in subdirectory_path.split(os.sep) or not subdirectory_path.startswith('egypt_server_storage'):
                    conn.sendall(b"[!] Restricted directory requested, download failed.")
                    logger.warning(f"[!] Restricted directory requested from {username}@{addr}")
                else:
                    directory_path = os.path.join(STORAGE_DIR, subdirectory_path)
            
                # Check if the real path after normalization is within the allowed STORAGE_DIR
                if not os.path.realpath(directory_path).startswith(os.path.realpath(STORAGE_DIR)):
                    conn.sendall(b"[!] Invalid directory path, download failed.")
                    logger.warning(f"[!] Invalid directory requested from {username}@{addr}")
                
                file_name = args[0]
                file_path = os.path.join(STORAGE_DIR, file_name)
                logger.info(f"[*] Download to {username}@{addr}")

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
                list_results = list_files(STORAGE_DIR)
                conn.sendall(list_results.encode('utf-8'))
                logger.info(f"[*] File list requested from {username}@{addr}")

            else:
                conn.sendall(b"[!] Invalid command.")

    except Exception as e:
        logger.error(f"[!] Error handling client {username}@{addr}: {e}")
    finally:
        logger.info(f"[-] Disconnection from {username}@{addr}")
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

def login(conn, addr):
    username = ""
    global username
    try:
        credentials = conn.recv(4096).decode('utf-8')
        if not credentials:
            logger.warning(f"[!] Invalid client submission.")
        username, password_hash = credentials.split(' ')
        
        if username in creds and creds[username] == password_hash:
            logger.info(f"[+] {username}@{addr} authenticated successfully.")
            conn.sendall(b"[+] Login successful.")
            return True
        else:
            logger.warning(f"[!] Authentication failed for {username}@{addr}.")
            conn.sendall(b"[!] Login failed.")
    except Exception as e:
        logger.error(f"[!] Error handling login from {user}@{addr}: {e}")
        conn.sendall(b"[!] Login error.")
    return False

def main():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        logger.info(f"[*] Secure server listening on {HOST}:{PORT}")
        while True:
            conn, addr = server_socket.accept()
            sconn = context.wrap_socket(conn, server_side=True)
            threading.Thread(target=handle_client, args=(sconn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
