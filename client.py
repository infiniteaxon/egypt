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
import getpass

# Server settings
SERVER_IP = 'x.x.x.x'
SERVER_PORT = xxxxx

# Encryption password
ENC_PASSWORD = getpass.getpass("[!] Input encryption password: ")

# Since the server is just a storage site, we can use a key derived from the password
key = base64.urlsafe_b64encode(hashlib.sha256(ENC_PASSWORD.encode()).digest())
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

def upload_file(ssock, file_name):
    # Get storage instructions
    directory = input("Enter the subdirectory for upload (leave blank for root): ").strip()
    full_path = os.path.join(CLIENT_DIR, file_name)
    
    if not os.path.exists(full_path):
        print("[!] File does not exist.")
        return
    
    encrypted_data, file_hash = encrypt_file(full_path)
    file_size = len(encrypted_data)
    command = f"UPLOAD {directory} {file_name} {file_size} {file_hash}"
    
    ssock.sendall(command.encode('utf-8'))
    ssock.sendall(encrypted_data)
    
    response = ssock.recv(1024).decode('utf-8')
    print(response)

def download_file(ssock, file_path):
    # Request file
    ssock.sendall(f"DOWNLOAD {file_path}".encode('utf-8'))
    
    # Handle server response for file download
    header = ssock.recv(1024).decode('utf-8')
    if not header:
        print("[-] Server closed the connection.")
        return
    header_parts = header.split()
    if len(header_parts) != 2:
        print("[!] Invalid response from server.")
        return
    
    file_size, server_file_hash = int(header_parts[0]), header_parts[1]
    
    # Adjusting local file path to include subdirectory
    local_file_path = os.path.join(CLIENT_DIR, os.path.basename(file_path))
    os.makedirs(os.path.dirname(local_file_path), exist_ok=True)
    
    # Receive file content
    received_data = b''
    while len(received_data) < file_size:
        chunk = ssock.recv(min(4096, file_size - len(received_data)))
        if not chunk:
            print("[-] Connection closed by the server.")
            return
        received_data += chunk

    # Verify file hash
    if hash_file(received_data) != server_file_hash:
        print("[!] File hash mismatch! The file may have been tampered with.")
        return
    
    # Decrypt and save the file
    decrypted_data = decrypt_file(received_data)
    with open(local_file_path, 'wb') as file:
        file.write(decrypted_data)
    print("[+] File downloaded and decrypted successfully.")


def request_file_list(ssock):
    try:
        ssock.sendall("LIST".encode('utf-8'))
        response = ssock.recv(4096).decode('utf-8')
        if response.strip():
            # Convert the CSV data to a DataFrame
            df = pd.read_csv(StringIO(response), sep=",")
            # Format and print
            print(tabulate(df, headers='keys', tablefmt='pipe', showindex=False))
        else:
            print("[!] No files found in storage.")
    except Exception as e:
        print(f"[!] Failed to request file list: {e}")

def clear():
    time.sleep(2)
    os_system = platform.system()
    if os_system == "Windows":
        os.system('cls')
        return
    else:
        os.system('clear')
        return

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login(ssock):
    username = input("Username: ")
    password = getpass.getpass("Password: ")  # Password input is now hidden
    password_hash = hash_password(password)
    credentials = f"{username} {password_hash}".encode('utf-8')
    ssock.sendall(credentials)
    
    response = ssock.recv(4096).decode('utf-8')
    print(response)
    if "Login successful" in response:
        return True
    else:
        return False

def main():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((SERVER_IP, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_IP) as ssock:
            print(f"[+] Securely connected to server at {SERVER_IP}:{SERVER_PORT}")
            
            login(ssock)

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
                    request_file_list(ssock)
                    file_name = input("\nEnter the filename to download: ")
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
