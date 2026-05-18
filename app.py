import os
import hashlib

from flask import Flask, render_template, request, redirect

from blockchain.blockchain import Blockchain

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user
)

app = Flask(__name__)

app.secret_key = 'secretkey'

login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = 'login'

# AES Secret Key
key = get_random_bytes(16)

blockchain = Blockchain()


# User Class
class User(UserMixin):

    def __init__(self, id):
        self.id = id


# Default User
users = {
    'admin': {
        'password': 'admin123'
    }
}


# Load User
@login_manager.user_loader
def load_user(user_id):

    return User(user_id)


UPLOAD_FOLDER = 'uploads'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# SHA-256 Hash Function
def generate_hash(filepath):

    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:

        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


# AES File Encryption
def encrypt_file(filepath):

    cipher = AES.new(key, AES.MODE_CBC)

    with open(filepath, 'rb') as f:
        file_data = f.read()

    encrypted_data = cipher.encrypt(
        pad(file_data, AES.block_size)
    )

    encrypted_path = filepath + '.enc'

    with open(encrypted_path, 'wb') as f:

        f.write(cipher.iv)
        f.write(encrypted_data)

    return encrypted_path


# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        if username in users and users[username]['password'] == password:

            user = User(username)

            login_user(user)

            return redirect('/dashboard')

        return '''
        <h2>Invalid Username or Password</h2>
        '''

    return render_template('login.html')


# Home Page
@app.route('/')
def home():
    return render_template('index.html')


# Dashboard
@login_required
@app.route('/dashboard')
def dashboard():

    total_blocks = len(blockchain.chain)

    total_files = total_blocks - 1

    return render_template(
        'dashboard.html',
        total_blocks=total_blocks,
        total_files=total_files
    )


# Upload Route
@app.route('/upload', methods=['POST'])
def upload():

    file = request.files['file']

    if file:

        filepath = os.path.join(
            app.config['UPLOAD_FOLDER'],
            file.filename
        )

        file.save(filepath)

        # Encrypt File
        encrypted_file = encrypt_file(filepath)

        print("Encrypted File:", encrypted_file)

        # Generate SHA-256 Hash
        file_hash = generate_hash(filepath)

        # Get Previous Block Hash
        previous_hash = blockchain.chain[-1]['hash']

        # Create Blockchain Block
        block = blockchain.create_block(
            previous_hash,
            file_hash
        )

        print(block)

        return f'''
        <h2>File Uploaded Successfully</h2>

        <p><b>SHA-256 Hash:</b></p>
        <p>{file_hash}</p>

        <p><b>Encrypted File:</b></p>
        <p>{encrypted_file}</p>

        <p><b>Block Number:</b></p>
        <p>{block['index']}</p>

        <br>

        <a href="/dashboard">
            Open Dashboard
        </a>

        <br><br>

        <a href="/verify">
            Verify File Integrity
        </a>

        <br><br>

        <a href="/blockchain">
            View Blockchain
        </a>

        <br><br>

        <a href="/logout">
            Logout
        </a>
        '''

    return "No File Selected"


# View Blockchain
@app.route('/blockchain')
def view_blockchain():

    return {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }


# Verify Integrity
@app.route('/verify', methods=['GET', 'POST'])
def verify():

    if request.method == 'POST':

        file = request.files['file']

        if file:

            filepath = os.path.join(
                app.config['UPLOAD_FOLDER'],
                file.filename
            )

            file.save(filepath)

            # Generate New Hash
            new_hash = generate_hash(filepath)

            # Verify with Blockchain
            for block in blockchain.chain:

                if block['file_hash'] == new_hash:

                    return f'''
                    <h2 style="color:green;">
                    ✔ File Integrity Verified
                    </h2>

                    <p>File is Safe</p>

                    <a href="/dashboard">
                        Open Dashboard
                    </a>
                    '''

            return f'''
            <h2 style="color:red;">
            ⚠ File Tampered
            </h2>

            <p>Integrity Verification Failed</p>

            <a href="/dashboard">
                Open Dashboard
            </a>
            '''

    return render_template('verify.html')


# Logout Route
@app.route('/logout')
@login_required
def logout():

    logout_user()

    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)