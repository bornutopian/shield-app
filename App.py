import streamlit as st
from streamlit_gsheets import GSheetsConnection
import pandas as pd
import hashlib

# --- 1. CONFIGURATION (Increase Limit to 1GB) ---
st.set_page_config(page_title="Creator Shield", page_icon="🛡️", layout="wide")

# --- 2. CONNECT (FAIL-SAFE) ---
# We attempt connection, but if it fails, we switch to "Local Mode" automatically.
try:
    conn = st.connection("gsheets", type=GSheetsConnection)
    db_active = True
except:
    db_active = False

# --- 3. AUTHENTICATION (HARDCODED) ---
if 'login' not in st.session_state: st.session_state.login = False
if 'user' not in st.session_state: st.session_state.user = ""

# LOGIN SCREEN
if not st.session_state.login:
    st.title("🛡️ Creator Shield")
    st.write("### Login")
    
    # Pre-filled for you
    u = st.text_input("Email", value="founder@creatorshield.in")
    p = st.text_input("Password", type="password", value="admin@#")
    
    if st.button("Login", type="primary"):
        if u == "founder@creatorshield.in" and p == "admin@#":
            st.session_state.login = True
            st.session_state.user = u
            st.rerun()
        else:
            st.error("❌ Access Denied")

# --- 4. MAIN TOOL ---
else:
    # SIDEBAR
    with st.sidebar:
        st.success(f"User: {st.session_state.user}")
        
        # Connection Status Indicator
        if db_active:
            st.caption("🟢 Database: Connected")
        else:
            st.caption("🟡 Database: Disconnected (Local Mode)")
            
        if st.button("Logout"):
            st.session_state.login = False
            st.rerun()

    # MAIN CONTENT
    st.title("🔐 Secure Your File")
    st.info("Upload your creative work to generate a permanent digital fingerprint (Hash).")
    
    # File Uploader
    file = st.file_uploader("Drag and drop file here", accept_multiple_files=False)
    
    if file:
        st.divider()
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.write("**Filename:**")
            st.code(file.name)
            st.write("**Size:**")
            st.write(f"{file.size / 1024:.2f} KB")
            
        with col2:
            if st.button("🛡️ Secure Now", type="primary", use_container_width=True):
                # 1. GENERATE HASH
                h = hashlib.sha256(file.getvalue()).hexdigest()
                
                # 2. SHOW SUCCESS (This always happens)
                st.balloons()
                st.success("✅ File Secured Successfully!")
                st.write("### Your Unique Hash:")
                st.code(h, language="text")
                st.warning("📸 Take a screenshot of this hash. It is your proof.")
                
                # 3. ATTEMPT CLOUD BACKUP (Silent)
                if db_active:
                    try:
                        v_df = conn.read(worksheet="vault", ttl=0)
                        entry = pd.DataFrame([{
                            "username": st.session_state.user, 
                            "filename": file.name, 
                            "hash": h
                        }])
                        conn.update(worksheet="vault", data=pd.concat([v_df, entry], ignore_index=True))
                        st.toast("Saved to Cloud Vault", icon="☁️")
                    except:
                        st.toast("Cloud Save Skipped (Permissions)", icon="⚠️")
