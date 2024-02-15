import socket
import os
import hashlib
from cryptography.fernet import Fernet
import base64
import sys

# Server settings
SERVER_IP = '24.96.47.160'
SERVER_PORT = 32603

# Encryption password (In practice, use a more secure method for handling keys)
PASSWORD = str(input("Input password: "))

# Since the server is just a storage site, we can use a key derived from the password
key = base64.urlsafe_b64encode(hashlib.sha256(PASSWORD.encode()).digest())
cipher_suite = Fernet(key)

# Directory to sync
CLIENT_DIR = '/home/axon/egypt'

def hash_file(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher_suite.encrypt(file_data)
    return encrypted_data

def decrypt_file(encrypted_data):
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    return decrypted_data

def upload_file(sock, file_name):
    file_path = os.path.join(CLIENT_DIR, file_name)
    if not os.path.exists(file_path):
        print("File does not exist.")
        return

    file_hash = hash_file(file_path)
    encrypted_data = encrypt_file(file_path)
    file_size = len(encrypted_data)
    sock.sendall(f"UPLOAD {file_name} {file_size} {file_hash}".encode('utf-8'))
    sock.sendall(encrypted_data)
    response = sock.recv(1024)
    print(response.decode('utf-8'))

def download_file(sock, file_name):
    sock.sendall(f"DOWNLOAD {file_name}".encode('utf-8'))
    file_size_data, server_file_hash = sock.recv(1024).decode('utf-8').split()
    if file_size_data.isdigit():
        file_size = int(file_size_data)
        received_data = b''
        while len(received_data) < file_size:
            chunk = sock.recv(4096)
            if not chunk:
                break
            received_data += chunk

        decrypted_data = decrypt_file(received_data)
        file_path = os.path.join(CLIENT_DIR, file_name)
        local_file_hash = hashlib.sha256(decrypted_data).hexdigest()
        if local_file_hash != server_file_hash:
            print("File hash mismatch! The file may have been tampered with.")
            return

        with open(file_path, 'wb') as file:
            file.write(decrypted_data)
        print("File downloaded and decrypted successfully.")
    else:
        print("File not found on server.")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((SERVER_IP, SERVER_PORT))
        except Exception as e:
            print(f"Cannot connect to server: {e}")
            sys.exit(1)

        while True:
            print("\nMenu:")
            print("1. Upload file")
            print("2. Download file")
            print("3. Exit")
            choice = input("Enter your choice: ")

            if choice == '1':
                file_name = input("Enter the name of the file to upload: ")
                upload_file(s, file_name)
            elif choice == '2':
                file_name = input("Enter the name of the file to download: ")
                download_file(s, file_name)
            elif choice == '3':
                print("Exiting.")
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()