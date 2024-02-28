import socket
import os
import hashlib
from cryptography.fernet import Fernet
import base64
import sys
import platform
import ssl
import time
from tabulate import tabulate
import pandas as pd
from io import StringIO

# Server settings
SERVER_IP = 'x.x.x.x'
SERVER_PORT = xxxxx

# Encryption password
PASSWORD = str(input("[!] Input password: "))

# Since the server is just a storage site, we can use a key derived from the password
key = base64.urlsafe_b64encode(hashlib.sha256(PASSWORD.encode()).digest())
cipher_suite = Fernet(key)

# Directory to sync
CLIENT_DIR = '/home/axon/egypt'

def hash_file(file_data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_data)
    return sha256_hash.hexdigest()

def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher_suite.encrypt(file_data)
    return encrypted_data, hash_file(encrypted_data)

def decrypt_file(encrypted_data):
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    return decrypted_data

def upload_file(sock, file_name):
    file_path = os.path.join(CLIENT_DIR, file_name)
    if not os.path.exists(file_path):
        print("[!] File does not exist.")
        return

    encrypted_data, file_hash = encrypt_file(file_path)
    file_size = len(encrypted_data)
    sock.sendall(f"UPLOAD {file_name} {file_size} {file_hash}".encode('utf-8'))
    sock.sendall(encrypted_data)
    response = sock.recv(1024)
    print(response.decode('utf-8'))

def download_file(sock, file_name):
    # Request file
    sock.sendall(f"DOWNLOAD {file_name}".encode('utf-8'))
    
    # Receive the initial response with file size and hash
    response = sock.recv(1024).decode('utf-8')
    if not response:
        print("[-] Server closed the connection.")
        return
    response_parts = response.split()
    if len(response_parts) != 2:
        print("[!] Invalid response from server.")
        return
    
    file_size, server_file_hash = response_parts
    file_size = int(file_size)
    
    # Start receiving the file
    received_data = b''
    try:
        while len(received_data) < file_size:
            # Determine how much data we expect to receive
            bytes_to_receive = min(4096, file_size - len(received_data))
            chunk = sock.recv(bytes_to_receive)
            if not chunk:
                raise Exception("[-] Connection closed by the server.")
            received_data += chunk
    except Exception as e:
        print(f"[!] Download failed: {e}")
        return
    
    # File reception completed, verify hash
    local_file_hash = hash_file(received_data)
    if local_file_hash != server_file_hash:
        print("[!] File hash mismatch! The file may have been tampered with.")
        return
    
    # Decrypt and save the file
    decrypted_data = decrypt_file(received_data)
    file_path = os.path.join(CLIENT_DIR, file_name)
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)
    print("[+] File downloaded and decrypted successfully.")

def request_file_list(socket):
    try:
        socket.sendall("LIST".encode('utf-8'))
        response = socket.recv(4096).decode('utf-8')  # Adjust buffer size as needed
        if response.strip():
            # Convert the CSV data to a DataFrame
            df = pd.read_csv(StringIO(response), sep=",")
            # Format and print the table without lines between rows
            print(tabulate(df, headers='keys', tablefmt='pipe', showindex=False))
        else:
            print("[!] No files found in storage.")
    except Exception as e:
        print(f"[!] Failed to request file list: {e}")

def clear():
    time.sleep(1)
    os_system = platform.system()
    if os_system == "Windows":
        os.system('cls')
        return
    else:
        os.system('clear')
        return

def main():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((SERVER_IP, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_IP) as ssock:
            print(f"[+] Securely connected to server at {SERVER_IP}:{SERVER_PORT}")
            
            while True:
                print("\nAvailable options:")
                print("1. Upload file")
                print("2. Download file")
                print("3. List files")
                print("4. Exit")
                choice = input("Select an option: ")

                if choice == '1':
                    file_name = input("Enter the filename to upload: ")
                    upload_file(ssock, file_name)
                    clear()
                elif choice == '2':
                    file_name = input("Enter the filename to download: ")
                    download_file(ssock, file_name)
                    clear()
                elif choice == '3':
                    clear()
                    request_file_list(ssock)
                elif choice == '4':
                    print("Exiting.")
                    clear()
                    break
                else:
                    print("[!] Invalid choice.")

if __name__ == "__main__":
    main()
