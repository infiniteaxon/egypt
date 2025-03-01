from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import socket, ssl, os, hashlib, base64, io, csv
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename

# --- Configuration ---
SERVER_IP = 'localhost'
SERVER_PORT = 32603

app = Flask(__name__)
app.secret_key = 'CHANGE_THIS_SECRET_KEY'  # Replace with a secure secret key in production

# --- Utility Functions ---

def hash_file(data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data)
    return sha256_hash.hexdigest()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_cipher(enc_password):
    key = base64.urlsafe_b64encode(hashlib.sha256(enc_password.encode()).digest())
    return Fernet(key)

def encrypt_file_data(data, cipher):
    encrypted_data = cipher.encrypt(data)
    return encrypted_data

def decrypt_file_data(data, cipher):
    return cipher.decrypt(data)

def connect_to_server():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((SERVER_IP, SERVER_PORT))
    ssock = context.wrap_socket(sock, server_hostname=SERVER_IP)
    return ssock

def login_to_server(ssock, username, password):
    password_hash = hash_password(password)
    credentials = f"{username} {password_hash}".encode('utf-8')
    ssock.sendall(credentials)
    response = ssock.recv(4096).decode('utf-8')
    return response

# --- Flask Routes ---

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username    = request.form['username']
        password    = request.form['password']
        enc_password = request.form['enc_password']
        try:
            ssock = connect_to_server()
            response = login_to_server(ssock, username, password)
            ssock.close()
            if "Login successful" in response:
                session['username'] = username
                session['password'] = password
                session['enc_password'] = enc_password
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Login failed. Check your credentials.", "danger")
        except Exception as e:
            flash(f"Connection error: {str(e)}", "danger")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    try:
        ssock = connect_to_server()
        response = login_to_server(ssock, session['username'], session['password'])
        if "Login successful" not in response:
            flash("Session expired, please log in again.", "danger")
            return redirect(url_for('login'))
        ssock.sendall("LIST".encode('utf-8'))
        csv_response = ssock.recv(4096).decode('utf-8')
        ssock.close()
        files = []
        if csv_response.strip() and "No files found" not in csv_response:
            reader = csv.reader(csv_response.splitlines())
            next(reader)  # Skip header row
            for row in reader:
                if row:
                    files.append({
                        'filename': row[0].strip('"'),
                        'size': row[1],
                        'created': row[2].strip('"')
                    })
        return render_template('dashboard.html', files=files)
    except Exception as e:
        flash(f"Error fetching file list: {str(e)}", "danger")
        return render_template('dashboard.html', files=[])

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file part.", "danger")
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash("No selected file.", "danger")
            return redirect(request.url)
        subdirectory = request.form.get('subdirectory', '').strip()
        filename = secure_filename(file.filename)
        file_data = file.read()
        cipher = get_cipher(session['enc_password'])
        encrypted_data = encrypt_file_data(file_data, cipher)
        file_hash = hash_file(encrypted_data)
        file_size = len(encrypted_data)
        # Construct the UPLOAD command
        command = f"UPLOAD {subdirectory} {filename} {file_size} {file_hash}"
        try:
            ssock = connect_to_server()
            response = login_to_server(ssock, session['username'], session['password'])
            if "Login successful" not in response:
                flash("Session expired, please log in again.", "danger")
                return redirect(url_for('login'))
            ssock.sendall(command.encode('utf-8'))
            ssock.sendall(encrypted_data)
            server_response = ssock.recv(1024).decode('utf-8')
            ssock.close()
            flash(server_response, "info")
        except Exception as e:
            flash(f"Upload failed: {str(e)}", "danger")
        return redirect(url_for('dashboard'))
    return render_template('upload.html')

@app.route('/download/<path:filename>')
def download(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    try:
        ssock = connect_to_server()
        response = login_to_server(ssock, session['username'], session['password'])
        if "Login successful" not in response:
            flash("Session expired, please log in again.", "danger")
            return redirect(url_for('login'))
        command = f"DOWNLOAD {filename}"
        ssock.sendall(command.encode('utf-8'))
        metadata = ssock.recv(1024).decode('utf-8')
        if "restricted" in metadata or "not found" in metadata:
            flash(metadata, "danger")
            return redirect(url_for('dashboard'))
        parts = metadata.split(' ', 1)
        if len(parts) != 2:
            flash("Invalid metadata received from server.", "danger")
            return redirect(url_for('dashboard'))
        file_size = int(parts[0])
        server_file_hash = parts[1]
        received_data = b""
        while len(received_data) < file_size:
            chunk = ssock.recv(min(4096, file_size - len(received_data)))
            if not chunk:
                break
            received_data += chunk
        ssock.close()
        if hash_file(received_data) != server_file_hash:
            flash("File hash mismatch! The file may have been tampered with.", "danger")
            return redirect(url_for('dashboard'))
        cipher = get_cipher(session['enc_password'])
        decrypted_data = decrypt_file_data(received_data, cipher)
        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        flash(f"Download failed: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)

