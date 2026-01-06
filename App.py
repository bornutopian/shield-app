import streamlit as st
from streamlit_gsheets import GSheetsConnection
import pandas as pd
import hashlib

st.set_page_config(page_title="Creator Shield", page_icon="🛡️")

# --- 1. CONNECT ---
try:
    conn = st.connection("gsheets", type=GSheetsConnection)
except:
    st.error("⚠️ Connection Error. Check Secrets.")
    st.stop()

# --- 2. AUTH STATE ---
if 'login' not in st.session_state: st.session_state.login = False
if 'user' not in st.session_state: st.session_state.user = ""

# --- 3. LOGIN / REGISTER ---
if not st.session_state.login:
    st.title("🛡️ Creator Shield")
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    # LOGIN
    with tab1:
        u = st.text_input("Username", value="founder@creatorshield.in")
        p = st.text_input("Password", type="password", value="admin@#")
        
        if st.button("Login"):
            try:
                df = conn.read(worksheet="users", ttl=0)
                df = df.dropna(how="all")
                
                # Check match
                if not df.empty and ((df['username'] == u) & (df['password'] == p)).any():
                    st.session_state.login = True
                    st.session_state.user = u
                    st.rerun()
                else:
                    st.error("User not found. Please Register first!")
            except Exception as e:
                st.error(f"Error reading sheet: {e}")

    # REGISTER
    with tab2:
        st.write("Click below to create your Admin account.")
        new_u = st.text_input("New Email", value="founder@creatorshield.in")
        new_p = st.text_input("New Password", type="password", value="admin@#")
        
        if st.button("Sign Up"):
            try:
                df = conn.read(worksheet="users", ttl=0)
                # Create simple dataframe
                new_data = pd.DataFrame([{
                    "username": str(new_u), 
                    "password": str(new_p), 
                    "credits": "Unlimited"
                }])
                updated_df = pd.concat([df, new_data], ignore_index=True)
                conn.update(worksheet="users", data=updated_df)
                st.success("Admin Account Created! Go to Login.")
            except Exception as e:
                st.error(f"Error writing: {e}")

# --- 4. MAIN APP ---
else:
    st.sidebar.title(f"User: {st.session_state.user}")
    if st.sidebar.button("Logout"):
        st.session_state.login = False
        st.rerun()

    st.title("Secure Your File")
    file = st.file_uploader("Upload File")
    
    if file and st.button("Secure Now"):
        h = hashlib.sha256(file.getvalue()).hexdigest()
        
        # Save to Vault
        v_df = conn.read(worksheet="vault", ttl=0)
        entry = pd.DataFrame([{
            "username": st.session_state.user, 
            "filename": file.name, 
            "hash": h
        }])
        conn.update(worksheet="vault", data=pd.concat([v_df, entry], ignore_index=True))
        
        st.balloons()
        st.success(f"Secured! Hash: {h}")

