import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet

KEY_FILE ="simple_secret.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    else:
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
    return key
        
        
cipher = Fernet(load_key())


def init_db():
    conn = sqlite3.connect("simple.db")
    c = conn.cursor()
    c.execute("""
              CREATE TABLE IF NOT EXISTS orient(
                  label TEXT PRIMARY KEY,
                  encrypted_text TEXT,
                  passkey TEXT
                  )""")
    conn.commit()
    conn.close()
    
init_db()

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

st.title(" Secure Data Encrytion and Decryption App")
menu = ["Secure Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Choose METHOD", menu)

if choice == "Secure Data":
    st.header("Store a new Secret")
    
    label = st.text_input("Label (Unique ID) ")
    secret = st.text_area("Secret")
    password = st.text_input("Password (to Protect Your Secret) ", type="password")
    

if st.button("Encrypt and Save Secret"):
    if label and secret and password:
        conn = sqlite3.connect("simple.db")
        c = conn.cursor()
        
        encrypted = encrypt(secret)
        hash_key = hash_passkey(password)
        
        try:
            c.execute("INSERT INTO orient( label, encrypted_text, passkey) VALUES (?, ?, ?)", (label, encrypted, hash_key))
            conn.commit()
            st.success("Secret Saved Successfully")
        except sqlite3.IntegrityError:
            st.error("A secret with this label already exists. Please choose a different label.")
            conn.close()
    else:
        st.warning("Please fill in all fields before saving the secret.")
        
        
elif choice == "Retrieve Data":
    st.header("Retrieve Your Secret")
    
    label = st.text_input("Enter Your Label:")
    password = st.text_input("Password", type="password")
    
    if st.button("Descrypt"):
        if label and password:
            conn = sqlite3.connect("simple.db")
            c = conn.cursor()
            c.execute(" Select encrypted_text, passkey FROM orient WHERE label=?", (label,))
            result = c.fetchone()
            conn.close()
            
            if result:
                encrypted_text, stored_hash = result
                if hash_passkey(password) == stored_hash:
                    decrypted_text = decrypt(encrypted_text)
                    st.success("Here is your Secret")
                    st.code(decrypted_text)
                else:
                    st.error("Incorrect password. Please try again.")
            else:
                st.error("No secret found with the provided label.")
        else:
            st.warning("Please fill in all fields before Retrieveing the secret.")