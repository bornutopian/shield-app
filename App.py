import streamlit as st
from streamlit_gsheets import GSheetsConnection
import pandas as pd
import hashlib

# --- CONFIGURATION ---
st.set_page_config(page_title="Creator Shield", page_icon="🛡️")

# --- CONNECT TO GOOGLE SHEET ---
try:
    conn = st.connection("gsheets", type=GSheetsConnection)
except Exception as e:
    st.error(f"⚠️ Connection Error: {e}")
    st.stop()

# --- INITIALIZE SESSION ---
if 'logged_in' not in st.session_state: st.session_state.logged_in = False
if 'user_email' not in st.session_state: st.session_state.user_email = ""

# --- LOGIN & REGISTER TABS ---
if not st.session_state.logged_in:
    st.title("🛡️ Creator Shield")
    
    tab_login, tab_register = st.tabs(["Login", "Create Account"])

    # 1. LOGIN TAB
    with tab_login:
        email_input = st.text_input("Email", value="founder@creatorshield.in")
        pass_input = st.text_input("Password", type="password", value="admin@#")
        
        if st.button("Login", type="primary"):
            try:
                # Read the 'users' tab
                df = conn.read(worksheet="users", ttl=0)
                df = df.dropna(how="all") # Clean empty rows
                
                # Check for match
                user_found = df[
                    (df['username'] == email_input) & 
                    (df['password'] == pass_input)
                ]
                
                if not user_found.empty:
                    st.session_state.logged_in = True
                    st.session_state.user_email = email_input
                    st.rerun()
                else:
                    st.error("❌ Incorrect email or password.")
            except Exception as e:
                st.error(f"Database Error: {e}")

    # 2. REGISTER TAB
    with tab_register:
        st.write("Create a new admin account below.")
        new_email = st.text_input("New Email", key="new_email")
        new_pass = st.text_input("New Password", type="password", key="new_pass")
        
        if st.button("Sign Up"):
            if new_email and new_pass:
                try:
                    df = conn.read(worksheet="users", ttl=0)
                    # Add new user to the sheet
                    new_user_data = pd.DataFrame([{
                        "username": str(new_email),
                        "password": str(new_pass),
                        "credits": "Unlimited"
                    }])
                    updated_df = pd.concat([df, new_user_data], ignore_index=True)
                    conn.update(worksheet="users", data=updated_df)
                    st.success("✅ Account Created! Please go to Login.")
                except Exception as e:
                    st.error(f"Error saving data: {e}")
            else:
                st.warning("Please enter both email and password.")

# --- MAIN DASHBOARD (AFTER LOGIN) ---
else:
    # Sidebar
    st.sidebar.success(f"Logged in as: {st.session_state.user_email}")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()

    # Main Tool
    st.title("🔐 Secure Your Asset")
    st.write("Upload your creative file to timestamp and secure it on the database.")
    
    uploaded_file = st.file_uploader("Choose a file")
    
    if uploaded_file is not None:
        if st.button("Secure File Now", type="primary"):
            # 1. Create Hash
            file_bytes = uploaded_file.getvalue()
            file_hash = hashlib.sha256(file_bytes).hexdigest()
            
            # 2. Save to 'vault' Sheet
            try:
                vault_df = conn.read(worksheet="vault", ttl=0)
                new_entry = pd.DataFrame([{
                    "username": st.session_state.user_email,
                    "filename": uploaded_file.name,
                    "hash": file_hash
                }])
                conn.update(worksheet="vault", data=pd.concat([vault_df, new_entry], ignore_index=True))
                
                # 3. Success Message
                st.balloons()
                st.success("✅ File Secured Successfully!")
                st.code(f"Hash: {file_hash}", language="text")
                st.info("Take a screenshot of this hash for your records.")
            
            except Exception as e:
                st.error(f"Vault Error: {e}")
