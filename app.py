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

# ---------------- APP SETUP ---------------- #

app = Flask(__name__)

app.secret_key = 'secretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create uploads folder (important for Render)
os.makedirs("uploads", exist_ok=True)

# AES Key
key = get_random_bytes(16)

blockchain = Blockchain()

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# ---------------- USER SYSTEM ---------------- #

class User(UserMixin):
    def __init__(self, id):
        self.id = id


users = {
    'admin': {
        'password': 'admin123'
    }
}


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


# ---------------- HASH FUNCTION ---------------- #

def generate_hash(filepath):

    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


# ---------------- AES ENCRYPTION ---------------- #

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


# ---------------- ROUTES ---------------- #

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        if username in users and users[username]['password'] == password:

            user = User(username)
            login_user(user)

            return redirect('/dashboard')

        return "<h2>Invalid Credentials</h2>"

    return render_template('login.html')


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/dashboard')
@login_required
def dashboard():

    total_blocks = len(blockchain.chain)
    total_files = total_blocks - 1

    return render_template(
        'dashboard.html',
        total_blocks=total_blocks,
        total_files=total_files
    )


@app.route('/upload', methods=['POST'])
def upload():

    file = request.files['file']

    if file:

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        # Encrypt file
        encrypted_file = encrypt_file(filepath)

        # Hash file
        file_hash = generate_hash(filepath)

        # Blockchain
        previous_hash = blockchain.chain[-1]['hash']

        block = blockchain.create_block(previous_hash, file_hash)

        return f"""
        <h2>Upload Success</h2>
        <p>Hash: {file_hash}</p>
        <p>Encrypted File: {encrypted_file}</p>
        <p>Block Index: {block['index']}</p>

        <br>
        <a href="/dashboard">Go to Dashboard</a>
        """

    return "No File Selected"


@app.route('/verify', methods=['GET', 'POST'])
def verify():

    if request.method == 'POST':

        file = request.files['file']

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        new_hash = generate_hash(filepath)

        for block in blockchain.chain:
            if block['file_hash'] == new_hash:
                return "<h2 style='color:green'>✔ File Verified</h2>"

        return "<h2 style='color:red'>⚠ File Tampered</h2>"

    return render_template('verify.html')


@app.route('/blockchain')
def view_blockchain():
    return {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')


# ---------------- RENDER FIX (STEP 6) ---------------- #

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)