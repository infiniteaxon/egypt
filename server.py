import socket
import os
import threading
import hashlib
import ssl
import time
import logging

# Server settings
HOST = '0.0.0.0'
PORT = 32603

# SSL configuration
CERTFILE = 'server.crt'
KEYFILE = 'server.key'

# User credentials dictionary
creds = {"axon": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"}

# Directory for storing received files
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

    username = login(conn, addr)
    if not username:
        conn.close()
        return

    try:
        while True:
            data = conn.recv(1024).decode('utf-8')
            if not data:
                break

            command, *args = data.split()
            # Commands now pass `username` to ensure proper logging and functionality
            if command == 'UPLOAD':
                upload(conn, args, username, addr)
            elif command == 'DOWNLOAD':
                download(conn, args, username, addr)
            elif command == 'LIST':
                file_list(conn, username, addr)
            else:
                conn.sendall(b"[!] Invalid command.")
    except Exception as e:
        logger.error(f"[!] Error handling client {username}@{addr}: {e}")
    finally:
        logger.info(f"[-] Disconnection from {username}@{addr}")
        conn.close()

def login(conn, addr):
    try:
        credentials = conn.recv(4096).decode('utf-8')
        if not credentials:
            logger.warning(f"[!] Invalid client submission from {addr}")
            conn.sendall(b"[!] Login failed. Exiting...")
            conn.close()
            return None
        username, password_hash = credentials.split(' ')
        if username in creds and creds[username] == password_hash:
            logger.info(f"[+] {username}@{addr} authenticated successfully.")
            conn.sendall(b"[+] Login successful.")
            return username
        else:
            logger.warning(f"[!] Authentication failed for {username}@{addr}.")
            conn.sendall(b"[!] Login failed. Exiting...")
            conn.close()
            return None
    except Exception as e:
        logger.error(f"[!] Error during login: {e}")
        conn.sendall(b"[!] Login error.")
        return None

def upload(conn, args, username, addr):
    subdirectory = ''
    
    if len(args) == 3:
        file_name, file_size, client_file_hash = args
    elif len(args) == 4:
        subdirectory, file_name, file_size, client_file_hash = args
    else:
        # Send an error for incorrect number of arguments?
        return
    
    # Input validation and directory check
    is_valid, response = validate_directory(STORAGE_DIR, subdirectory)
    if not is_valid:
        conn.sendall(response.encode('utf-8'))
        logger.error(f"{response} from {username}@{addr}")
        return

    file_size = int(file_size) # Convert file size to int
    file_path = os.path.join(response, file_name)  # Construct the full file path

    # Create the directory if it doesn't exist
    os.makedirs(response, exist_ok=True) 

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

def download(conn, args, username, addr):
    if len(args) != 1:
        conn.sendall(b"[!] Incorrect number of arguments for download.")
        logger.error(f"[!] Incorrect number of arguments for download from {username}@{addr}")
        return

    file_name = args[0]
    
    # Input validation and directory check
    is_valid, file_path = validate_directory(STORAGE_DIR, file_name)
    if not is_valid:
        conn.sendall(file_path.encode('utf-8'))  # file_path contains the error message
        logger.error(f"{file_path} from {username}@{addr}")
        return

    # Get download data
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            file_data = f.read()

        server_file_hash = hash_file(file_data)
        file_size = len(file_data)
        # Send the file size and hash before sending the file content
        metadata = f"{file_size} {server_file_hash}"
        conn.sendall(metadata.encode('utf-8'))
        
        # Send the file content
        conn.sendall(file_data)
        logger.info(f"[*] File {file_name} sent to {username}@{addr}")
    else:
        conn.sendall(b"[!] File not found.")
        logger.warning(f"[!] File {file_name} not found for {username}@{addr}")

def file_list(conn, username, addr):
    files_found = ["Filename,Size (bytes),Created"]
    for root, dirs, files in os.walk(STORAGE_DIR):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(file_path, STORAGE_DIR)
            file_size = os.path.getsize(file_path)
            creation_date = time.ctime(os.path.getctime(file_path))
            files_found.append(f"\"{relative_path}\",{file_size},\"{creation_date}\"")
    list_results = "\n".join(files_found) if len(files_found) > 1 else "No files found in storage."
    conn.sendall(list_results.encode('utf-8'))
    logger.info(f"[*] File list requested from {username}@{addr}")

def validate_directory(STORAGE_DIR, path):
    # Normalize and resolve the absolute path upfront
    normalized_path = os.path.normpath(os.path.join(STORAGE_DIR, path))
    absolute_path = os.path.realpath(normalized_path)
    print(absolute_path)

    # Check for directory traversal attempts by examining the normalized path
    if ".." in normalized_path.split(os.sep) or not absolute_path.startswith(os.path.realpath(STORAGE_DIR)):
        return False, f"[!] Access to {normalized_path} is restricted."
    
    # The path is valid and within the storage directory
    return True, absolute_path

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
