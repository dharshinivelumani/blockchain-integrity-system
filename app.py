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

# ---------------- APP ---------------- #

app = Flask(__name__)
app.secret_key = "secretkey"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

os.makedirs("uploads", exist_ok=True)

key = get_random_bytes(16)

blockchain = Blockchain()

app.config["UPLOAD_FOLDER"] = "uploads"

# ---------------- USER ---------------- #

class User(UserMixin):
    def __init__(self, id):
        self.id = id


users = {
    "admin": {"password": "admin123"}
}


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# ---------------- HASH ---------------- #

def generate_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

# ---------------- AES ---------------- #

def encrypt_file(filepath):
    cipher = AES.new(key, AES.MODE_CBC)

    with open(filepath, "rb") as f:
        data = f.read()

    enc = cipher.encrypt(pad(data, AES.block_size))

    out_path = filepath + ".enc"

    with open(out_path, "wb") as f:
        f.write(cipher.iv)
        f.write(enc)

    return out_path

# ---------------- ROUTES ---------------- #

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        if u in users and users[u]["password"] == p:
            user = User(u)
            login_user(user)
            return redirect("/dashboard")

        return "<h2>Invalid Credentials</h2>"

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files["file"]

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)

    encrypted = encrypt_file(filepath)
    file_hash = generate_hash(filepath)

    prev_hash = blockchain.chain[-1]["hash"]
    block = blockchain.create_block(prev_hash, file_hash)

    return f"""
    <h2>Upload Success</h2>
    <p>Hash: {file_hash}</p>
    <p>Encrypted: {encrypted}</p>
    <p>Block: {block['index']}</p>
    """


@app.route("/verify", methods=["GET", "POST"])
@login_required
def verify():
    if request.method == "POST":
        file = request.files["file"]

        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)

        new_hash = generate_hash(filepath)

        for block in blockchain.chain:
            if block["file_hash"] == new_hash:
                return "<h2 style='color:green'>Verified</h2>"

        return "<h2 style='color:red'>Tampered</h2>"

    return render_template("verify.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


# ---------------- RENDER ENTRY ---------------- #

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)