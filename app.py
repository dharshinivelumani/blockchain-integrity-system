import os
import hashlib

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    send_file
)

from blockchain.blockchain import Blockchain

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from reportlab.pdfgen import canvas
from datetime import datetime

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user
)

# ---------------- APP ---------------- #

app = Flask(__name__)
app.secret_key = "secretkey"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Create uploads folder
os.makedirs("uploads", exist_ok=True)

# AES Secret Key
key = get_random_bytes(16)

# Blockchain
blockchain = Blockchain()

# Upload Folder
app.config["UPLOAD_FOLDER"] = "uploads"

# ---------------- USER ---------------- #

class User(UserMixin):

    def __init__(self, id):
        self.id = id


# Default Login User
users = {
    "admin": {
        "password": "admin123"
    }
}


@login_manager.user_loader
def load_user(user_id):

    return User(user_id)

# ---------------- HASH FUNCTION ---------------- #

def generate_hash(filepath):

    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:

        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()

# ---------------- AES ENCRYPTION ---------------- #

def encrypt_file(filepath):

    cipher = AES.new(key, AES.MODE_CBC)

    with open(filepath, "rb") as f:
        file_data = f.read()

    encrypted_data = cipher.encrypt(
        pad(file_data, AES.block_size)
    )

    encrypted_path = filepath + ".enc"

    with open(encrypted_path, "wb") as f:

        f.write(cipher.iv)
        f.write(encrypted_data)

    return encrypted_path

# ---------------- HOME ---------------- #

@app.route("/")
def home():

    return render_template("index.html")

# ---------------- LOGIN ---------------- #

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if username in users and users[username]["password"] == password:

            user = User(username)

            login_user(user)

            return redirect("/dashboard")

        return '''
        <h2>Invalid Username or Password</h2>
        '''

    return render_template("login.html")

# ---------------- DASHBOARD ---------------- #

@app.route("/dashboard")
@login_required
def dashboard():

    total_blocks = len(blockchain.chain)

    total_files = total_blocks - 1

    return render_template(
        "dashboard.html",
        total_blocks=total_blocks,
        total_files=total_files
    )

# ---------------- UPLOAD ---------------- #

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():

    if request.method == "POST":

        file = request.files["file"]

        if file:

            filepath = os.path.join(
                app.config["UPLOAD_FOLDER"],
                file.filename
            )

            # Save File
            file.save(filepath)

            # Encrypt File
            encrypted_file = encrypt_file(filepath)

            # Generate SHA-256 Hash
            file_hash = generate_hash(filepath)

            # Previous Block Hash
            previous_hash = blockchain.chain[-1]["hash"]

            # Create Blockchain Block
            block = blockchain.create_block(
                previous_hash,
                file_hash
            )

            return f'''
            <html>

            <head>

                <title>Upload Success</title>

                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

            </head>

            <body style="background:#f4f6f9;">

                <div class="container mt-5">

                    <div class="card p-4 shadow">

                        <h2 style="color:green;">
                            ✔ File Uploaded Successfully
                        </h2>

                        <hr>

                        <p>
                            <b>SHA-256 Hash:</b>
                        </p>

                        <p>{file_hash}</p>

                        <p>
                            <b>Encrypted File:</b>
                        </p>

                        <p>{encrypted_file}</p>

                        <p>
                            <b>Block Number:</b>
                        </p>

                        <p>{block['index']}</p>

                        <a href="/dashboard"
                           class="btn btn-primary">
                           Open Dashboard
                        </a>

                    </div>

                </div>

            </body>

            </html>
            '''

    return render_template("upload.html")

# ---------------- VERIFY ---------------- #

@app.route("/verify", methods=["GET", "POST"])
@login_required
def verify():

    if request.method == "POST":

        file = request.files["file"]

        if file:

            filepath = os.path.join(
                app.config["UPLOAD_FOLDER"],
                file.filename
            )

            # Save File
            file.save(filepath)

            # Generate New Hash
            new_hash = generate_hash(filepath)

            # ---------------- FIXED VERIFICATION ---------------- #

            verified = False

            # Skip Genesis Block
            for block in blockchain.chain[1:]:

                if block["file_hash"] == new_hash:

                    verified = True
                    break

            # ---------------- VERIFIED ---------------- #

            if verified:

                return '''
                <html>

                <head>

                    <title>Verification Success</title>

                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

                </head>

                <body style="background:#f4f6f9;">

                    <div class="container mt-5">

                        <div class="card p-4 shadow">

                            <h2 style="color:green;">
                                ✔ File Integrity Verified
                            </h2>

                            <hr>

                            <p class="mt-3">
                                File is Safe and Untampered.
                            </p>

                            <a href="/dashboard"
                               class="btn btn-success">
                               Back to Dashboard
                            </a>

                            <br><br>

                            <a href="/certificate"
                               class="btn btn-dark">
                               Download Certificate
                            </a>

                        </div>

                    </div>

                </body>

                </html>
                '''

            # ---------------- TAMPERED ---------------- #

            else:

                return '''
                <html>

                <head>

                    <title>Verification Failed</title>

                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

                </head>

                <body style="background:#f4f6f9;">

                    <div class="container mt-5">

                        <div class="card p-4 shadow">

                            <h2 style="color:red;">
                                ⚠ File Tampered
                            </h2>

                            <hr>

                            <p class="mt-3">
                                Integrity Verification Failed.
                            </p>

                            <a href="/dashboard"
                               class="btn btn-danger">
                               Back to Dashboard
                            </a>

                        </div>

                    </div>

                </body>

                </html>
                '''

    return render_template("verify.html")

# ---------------- BLOCKCHAIN ---------------- #

@app.route("/blockchain")
@login_required
def view_blockchain():

    return {
        "chain": blockchain.chain,
        "length": len(blockchain.chain)
    }

# ---------------- PDF CERTIFICATE ---------------- #

@app.route("/certificate")
@login_required
def certificate():

    file_path = "certificate.pdf"

    c = canvas.Canvas(file_path)

    # Title
    c.setFont("Helvetica-Bold", 24)
    c.drawString(150, 800, "Integrity Certificate")

    # Project
    c.setFont("Helvetica", 16)

    c.drawString(
        100,
        740,
        "Project:"
    )

    c.drawString(
        250,
        740,
        "Blockchain Integrity System"
    )

    # Status
    c.drawString(
        100,
        690,
        "Status:"
    )

    c.drawString(
        250,
        690,
        "Verified and Untampered"
    )

    # Generated Time
    c.drawString(
        100,
        640,
        "Generated On:"
    )

    c.drawString(
        250,
        640,
        str(datetime.now())
    )

    # Footer
    c.setFont("Helvetica-Oblique", 12)

    c.drawString(
        120,
        100,
        "Secure Blockchain Verification Certificate"
    )

    c.save()

    return send_file(
        file_path,
        as_attachment=True
    )

# ---------------- LOGOUT ---------------- #

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect("/login")

# ---------------- RENDER ENTRY ---------------- #

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 10000))

    app.run(
        host="0.0.0.0",
        port=port
    )