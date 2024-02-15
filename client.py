from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import socket
import os
import sys

# Server settings
SERVER_IP = '0.0.0.0'
SERVER_PORT = 32603

# Directory to sync
CLIENT_DIR = '/home/axom/egypt'

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Function to encrypt data with the public key
def encrypt_with_public_key(public_key, data):
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Function to decrypt data with the private key
def decrypt_with_private_key(private_key, encrypted_data):
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def upload_file(sock, file_name):
    file_path = os.path.join(CLIENT_DIR, file_name)
    if not os.path.exists(file_path):
        print("File does not exist.")
        return

    with open(file_path, 'rb') as file:
        file_data = file.read()

    encrypted_data = encrypt_with_public_key(public_key, file_data)
    file_size = len(encrypted_data)
    sock.sendall(f"UPLOAD {file_name} {file_size}".encode('utf-8'))
    sock.sendall(encrypted_data)
    response = sock.recv(1024)
    print(response.decode('utf-8'))

def download_file(sock, file_name):
    sock.sendall(f"DOWNLOAD {file_name}".encode('utf-8'))
    file_size_data = sock.recv(1024).decode('utf-8')
    if file_size_data.isdigit():
        file_size = int(file_size_data)
        received_data = b''
        while len(received_data) < file_size:
            chunk = sock.recv(4096)
            if not chunk:
                break
            received_data += chunk

        decrypted_data = decrypt_with_private_key(private_key, received_data)
        file_path = os.path.join(CLIENT_DIR, file_name)
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
