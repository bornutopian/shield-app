import streamlit as st
from streamlit_gsheets import GSheetsConnection
import pandas as pd
import hashlib

st.set_page_config(page_title="Creator Shield", page_icon="🛡️")

# --- CONNECT ---
conn = st.connection("gsheets", type=GSheetsConnection)

# --- AUTH ---
if 'login' not in st.session_state: st.session_state.login = False
if 'user' not in st.session_state: st.session_state.user = ""

if not st.session_state.login:
    st.title("🛡️ Creator Shield")
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    # LOGIN
    with tab1:
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Login"):
            try:
                df = conn.read(worksheet="users", ttl=0)
                df = df.dropna(how="all")
                if not df.empty and ((df['username'] == u) & (df['password'] == p)).any():
                    st.session_state.login = True
                    st.session_state.user = u
                    st.rerun()
                else:
                    st.error("Access Denied")
            except Exception as e:
                st.error(f"Database Error: {e}")

    # REGISTER
    with tab2:
        new_u = st.text_input("New Email")
        new_p = st.text_input("New Password", type="password")
        if st.button("Sign Up"):
            try:
                df = conn.read(worksheet="users", ttl=0)
                new_data = pd.DataFrame([{"username": str(new_u), "password": str(new_p), "credits": "Unlimited"}])
                updated_df = pd.concat([df, new_data], ignore_index=True)
                conn.update(worksheet="users", data=updated_df)
                st.success("Created! Please Login.")
            except Exception as e:
                st.error(f"Write Error: {e}")

else:
    st.sidebar.write(f"User: {st.session_state.user}")
    if st.sidebar.button("Logout"):
        st.session_state.login = False
        st.rerun()

    st.title("Secure File")
    f = st.file_uploader("Upload")
    if f and st.button("Secure Now"):
        h = hashlib.sha256(f.getvalue()).hexdigest()
        st.success(f"Secured! Hash: {h}")
        # Save to vault
        v_df = conn.read(worksheet="vault", ttl=0)
        entry = pd.DataFrame([{"username": st.session_state.user, "filename": f.name, "hash": h}])
        conn.update(worksheet="vault", data=pd.concat([v_df, entry], ignore_index=True))
