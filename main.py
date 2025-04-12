import streamlit as st
import hashlib
import json
from cryptography.fernet import Fernet, InvalidToken

# Load and save data from/to JSON file
def load_data():
    try:
        with open('stored_data.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_data():
    with open('stored_data.json', 'w') as f:
        json.dump(st.session_state.stored_data, f)

# ---------- Setup ----------
st.set_page_config(page_title="Secure Data Vault", page_icon="🔐", layout="centered")

# One-time Fernet key
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
cipher = Fernet(st.session_state.fernet_key)

# Session variables
if "users" not in st.session_state:
    st.session_state.users = {}
if "stored_data" not in st.session_state:
    st.session_state.stored_data = load_data()  # Load from JSON file if exists
if "logged_in_user" not in st.session_state:
    st.session_state.logged_in_user = None

# ---------- Helper Functions ----------
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(username, passkey):
    data = st.session_state.stored_data[username]
    if data["attempts"] >= 3:
        return "locked"
    if hash_text(passkey) == data["passkey"]:
        try:
            decrypted = cipher.decrypt(data["encrypted"].encode()).decode()
            data["attempts"] = 0
            save_data()  # Save data after successful decryption
            return decrypted
        except InvalidToken:
            data["attempts"] += 1
            save_data()  # Save data after failed decryption attempt
            return None
    else:
        data["attempts"] += 1
        save_data()  # Save data after failed passkey attempt
        return None

# ---------- Register ----------
def register():
    st.subheader("📝 Register")
    new_user = st.text_input("New Username")
    new_pass = st.text_input("New Password", type="password")
    if st.button("Register"):
        if new_user in st.session_state.users:
            st.error("🚫 Username already exists!")
        elif new_user and new_pass:
            st.session_state.users[new_user] = {"password": hash_text(new_pass)}
            st.success("✅ Registration successful! Please login.")
        else:
            st.warning("⚠️ Please fill all fields.")

# ---------- Login ----------
def login():
    st.subheader("🔐 Login")
    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")
    if st.button("Login"):
        if user in st.session_state.users and st.session_state.users[user]["password"] == hash_text(pwd):
            st.session_state.logged_in_user = user
            if user not in st.session_state.stored_data:
                st.session_state.stored_data[user] = {"encrypted": "", "passkey": "", "attempts": 0}
            save_data()  # Save data after login
            st.success("✅ Logged in!")
            st.rerun()
        else:
            st.error("❌ Invalid credentials!")

# ---------- Store Data ----------
def store_data():
    st.subheader("📂 Store Data")
    data = st.text_area("Enter secret data:")
    passkey = st.text_input("Set passkey:", type="password")
    if st.button("Encrypt & Save"):
        if data and passkey:
            encrypted = encrypt_data(data)
            st.session_state.stored_data[st.session_state.logged_in_user] = {
                "encrypted": encrypted,
                "passkey": hash_text(passkey),
                "attempts": 0
            }
            save_data()  # Save data to JSON file
            st.success("✅ Encrypted and stored!")
            st.code(encrypted)
        else:
            st.warning("⚠️ Please enter all fields!")

# ---------- Retrieve Data ----------
def retrieve_data():
    st.subheader("🔍 Retrieve Data")
    passkey = st.text_input("Enter passkey to decrypt", type="password")
    if st.button("Decrypt"):
        user = st.session_state.logged_in_user
        result = decrypt_data(user, passkey)
        if result == "locked":
            st.warning("🔒 Too many wrong attempts! Logging out...")
            st.session_state.logged_in_user = None
            st.rerun()
        elif result:
            st.success("✅ Decryption successful")
            st.code(result)
        else:
            attempts_left = 3 - st.session_state.stored_data[user]["attempts"]
            st.error(f"❌ Incorrect passkey! {attempts_left} attempts left.")

# ---------- Logout ----------
def logout():
    st.session_state.logged_in_user = None
    save_data()  # Save data after logout
    st.success("👋 Logged out!")
    st.rerun()
# ---------- Styling ----------
st.markdown("""
    <style>
        .main {
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 20px;
        }
        .title {
            font-size: 90px;
            font-weight: bold;
            color: #4CAF50;
        }
        .subtitle {
            font-size: 1.1em;
            color: #666666;
        }
    </style>
""", unsafe_allow_html=True)

# ---------- Header UI ----------
with st.container():
    st.markdown('<p style="font-size: 2.5em; font-weight: bold; text-align: center;">🔒 Secure Data Encryption System</p>', unsafe_allow_html=True)
    st.markdown('<p style=" text-align: center;" class="subtitle">A secure way to encrypt, store, and retrieve your secret data with passkey protection.</p>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    
# ---------- Sidebar Navigation ----------
st.sidebar.title("🔐 Secure App Menu")

if st.session_state.logged_in_user:
    st.sidebar.success(f"👋 Welcome, **{st.session_state.logged_in_user}**!")
    option = st.sidebar.radio("Navigate", ["🏠 Home", "📂 Store Data", "🔍 Retrieve Data", "🚪 Logout"])

    if option == "🏠 Home":
        with st.container():
            st.markdown("""
            <div style='
            border-radius: 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            text-align: center;
            '>
            <h2 style='font-size: 2.3em; color: #; margin-bottom: 10px;'>👋 Welcome, <span style="color: #4CAF50;">{}</span>!</h2>
            <p style='font-size: 1.1em; color: #; margin-top: 0;'>
                You're logged into <strong>Secure Data Vault</strong> 🧠<br>
                Store and retrieve your confidential info with military-grade encryption 🔐
            </p>
            <hr style='margin: 30px 0; border: 1px solid #ddd;'>
            
            """.format(st.session_state.logged_in_user), unsafe_allow_html=True)
            
    elif option == "📂 Store Data":
        store_data()
    elif option == "🔍 Retrieve Data":
        retrieve_data()
    elif option == "🚪 Logout":
        logout()

else:
    st.sidebar.info("Please login or register to continue.")
    option = st.sidebar.radio("Select", ["🔐 Login", "📝 Register"])

    if option == "🔐 Login":
        login()
    elif option == "📝 Register":
        register()
