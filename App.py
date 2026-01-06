import streamlit as st
from streamlit_gsheets import GSheetsConnection
import pandas as pd
import hashlib

# --- CONFIGURATION ---
st.set_page_config(page_title="Creator Shield", page_icon="🛡️")

# --- CONNECT TO DATABASE ---
# We try to connect, but if it fails, the App won't crash immediately
try:
    conn = st.connection("gsheets", type=GSheetsConnection)
except:
    conn = None

# --- AUTH STATE ---
if 'login' not in st.session_state: st.session_state.login = False
if 'user' not in st.session_state: st.session_state.user = ""

# --- LOGIN LOGIC ---
if not st.session_state.login:
    st.title("🛡️ Creator Shield")
    
    # 1. INPUTS
    st.write("### Login")
    u = st.text_input("Email", value="founder@creatorshield.in")
    p = st.text_input("Password", type="password", value="admin@#")
    
    if st.button("Login"):
        # --- MASTER KEY (BYPASSES DATABASE) ---
        if u == "founder@creatorshield.in" and p == "admin@#":
            st.session_state.login = True
            st.session_state.user = u
            st.success("✅ Master Admin Verified")
            st.rerun()
            
        # --- REGULAR USER CHECK (DATABASE) ---
        else:
            if conn:
                try:
                    df = conn.read(worksheet="users", ttl=0)
                    df = df.dropna(how="all")
                    if not df.empty and ((df['username'] == u) & (df['password'] == p)).any():
                        st.session_state.login = True
                        st.session_state.user = u
                        st.rerun()
                    else:
                        st.error("❌ User not found.")
                except:
                    st.error("⚠️ Database Error (But Admin can still login)")
            else:
                st.error("⚠️ Connection broken.")

# --- MAIN APP ---
else:
    st.sidebar.success(f"Logged in: {st.session_state.user}")
    if st.sidebar.button("Logout"):
        st.session_state.login = False
        st.rerun()

    st.title("🔐 Secure Your File")
    
    # TABS FOR ADMIN
    if st.session_state.user == "founder@creatorshield.in":
        mode = st.radio("Mode", ["Secure File", "Add New User"])
    else:
        mode = "Secure File"

    # 1. SECURE FILE MODE
    if mode == "Secure File":
        file = st.file_uploader("Upload a file")
        if file and st.button("Secure Now"):
            h = hashlib.sha256(file.getvalue()).hexdigest()
            
            # Try to save to vault
            try:
                v_df = conn.read(worksheet="vault", ttl=0)
                entry = pd.DataFrame([{
                    "username": st.session_state.user, 
                    "filename": file.name, 
                    "hash": h
                }])
                conn.update(worksheet="vault", data=pd.concat([v_df, entry], ignore_index=True))
                st.balloons()
                st.success(f"Secured! Hash: {h}")
            except Exception as e:
                # Even if save fails, show the hash
                st.warning(f"Database write failed ({e}), but here is your Hash:")
                st.code(h)

    # 2. ADD USER MODE (ADMIN ONLY)
    elif mode == "Add New User":
        st.write("### Create New Account")
        new_u = st.text_input("New User Email")
        new_p = st.text_input("New User Password")
        if st.button("Create Account"):
            try:
                df = conn.read(worksheet="users", ttl=0)
                new_data = pd.DataFrame([{
                    "username": str(new_u), 
                    "password": str(new_p), 
                    "credits": "Unlimited"
                }])
                conn.update(worksheet="users", data=pd.concat([df, new_data], ignore_index=True))
                st.success("User Created!")
            except Exception as e:
                st.error(f"Failed to add user: {e}")
