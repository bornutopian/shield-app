import streamlit as st
import pandas as pd
import hashlib
from datetime import datetime, timedelta
from fpdf import FPDF

# --- CONFIGURATION ---
st.set_page_config(page_title="Creator Shield", page_icon="🛡️", layout="wide")

# --- MOCK DATABASE (TEST MODE) ---
if 'mock_db' not in st.session_state:
    st.session_state.mock_db = pd.DataFrame(columns=["username", "password", "credits"])

# --- ASSETS & FUNCTIONS ---
def generate_certificate(username, filename, file_hash, timestamp):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 24)
    pdf.cell(0, 20, "Certificate of Registration", ln=True, align='C')
    
    pdf.set_font("Arial", size=12)
    pdf.ln(20)
    pdf.cell(0, 10, f"This document certifies that the file listed below", ln=True, align='C')
    pdf.cell(0, 10, f"has been secured on the Creator Shield Blockchain.", ln=True, align='C')
    
    pdf.ln(20)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(50, 10, "Owner:", border=0)
    pdf.set_font("Arial", size=14)
    pdf.cell(0, 10, f"{username}", ln=True)
    
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(50, 10, "File Name:", border=0)
    pdf.set_font("Arial", size=14)
    pdf.cell(0, 10, f"{filename}", ln=True)
    
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(50, 10, "Timestamp (IST):", border=0)
    pdf.set_font("Arial", size=14)
    pdf.cell(0, 10, f"{timestamp}", ln=True)
    
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Digital Fingerprint (SHA-256):", ln=True)
    pdf.set_font("Courier", size=10)
    pdf.multi_cell(0, 10, file_hash)
    
    pdf.ln(30)
    pdf.set_font("Arial", 'I', 10)
    pdf.cell(0, 10, "Creator Shield - Intellectual Property Protection Service", ln=True, align='C')
    
    return pdf.output(dest='S').encode('latin-1')

# --- SESSION STATE ---
if 'login' not in st.session_state: st.session_state.login = False
if 'user' not in st.session_state: st.session_state.user = ""

# --- AUTHENTICATION ---
if not st.session_state.login:
    
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        st.title("🛡️ Creator Shield")
    
    tab_login, tab_register = st.tabs(["Sign In", "Create Account"])
    
    # 1. SIGN IN PAGE
    with tab_login:
        st.write("### Welcome Back")
        email = st.text_input("Email Address", key="login_email")
        password = st.text_input("Password", type="password", key="login_pass")
        
        col_login, col_forgot = st.columns([1, 2])
        with col_login:
            if st.button("Sign In", type="primary", use_container_width=True):
                
                # --- MASTER LOGIN (FOUNDER) ---
                if email == "founder@creatorshield.in" and password == "admin@#":
                if email == "test@gmail.com" and password == "123":
                    st.session_state.login = True
                    st.session_state.user = email
                    st.rerun()
                
                # --- USER LOGIN (TEST DB) ---
                else:
                    df = st.session_state.mock_db
                    if not df.empty and ((df['username'] == email) & (df['password'] == password)).any():
                        st.session_state.login = True
                        st.session_state.user = email
                        st.rerun()
                    else:
                        st.error("Incorrect email or password.")
        
        with col_forgot:
            st.markdown("""
            <div style="text-align: right; padding-top: 10px;">
                <a href="mailto:support@creatorshield.in?subject=Reset Password" style="text-decoration: none; color: #FF4B4B;">Forgot Password?</a>
            </div>
            """, unsafe_allow_html=True)

    # 2. REGISTRATION PAGE
    with tab_register:
        st.write("### Join Creator Shield")
        st.link_button("📝 Secure Your Data (Form)", "https://docs.google.com/forms/d/e/1FAIpQLSdeP0149pOVn8GmQ5dkpjbcC8uPYK_sWpAPGxI8JXbCDHABUw/viewform?usp=header", type="primary", use_container_width=True)
        
        st.divider()
        st.write("For Admin Use Only (Test Mode):")
        new_u = st.text_input("New Email", key="new_u")
        new_p = st.text_input("New Password", type="password", key="new_p")
        
        if st.button("Create User (3 Credits)"):
            # SAVE TO MOCK DB
            new_data = pd.DataFrame([{"username": new_u, "password": new_p, "credits": 3}])
            st.session_state.mock_db = pd.concat([st.session_state.mock_db, new_data], ignore_index=True)
            st.success("✅ Test User Created! Go to Sign In.")

# --- DASHBOARD (LOGGED IN) ---
else:
    # Check Credits
    current_credits = "Unlimited"
    if st.session_state.user != "founder@creatorshield.in":
        # Look up in mock db
        user_row = st.session_state.mock_db[st.session_state.mock_db['username'] == st.session_state.user]
        if not user_row.empty:
            current_credits = user_row.iloc[0]['credits']

    with st.sidebar:
        st.success(f"👤 {st.session_state.user}")
        st.info(f"Credits Left: **{current_credits}**")
        if st.button("Logout"):
            st.session_state.login = False
            st.rerun()

    st.title("🔐 Secure New Asset")
    
    uploaded_file = st.file_uploader("Upload File (Max 1GB)", help="Images, Audio, Video, Scripts")
    
    if uploaded_file:
        st.divider()
        c1, c2 = st.columns([1, 2])
        with c1:
            st.metric("File Size", f"{uploaded_file.size / 1024:.1f} KB")
        
        with c2:
            if st.button("🛡️ SECURE & CERTIFY", type="primary", use_container_width=True):
                
                # --- CREDIT CHECK LOGIC ---
                allow_upload = False
                
                # 1. Founder is always allowed
                if st.session_state.user == "founder@creatorshield.in":
                    allow_upload = True
                
                # 2. Check Regular User
                else:
                    if isinstance(current_credits, (int, float)) and current_credits > 0:
                        allow_upload = True
                        # Deduct Credit in Mock DB
                        idx = st.session_state.mock_db[st.session_state.mock_db['username'] == st.session_state.user].index[0]
                        st.session_state.mock_db.at[idx, 'credits'] = current_credits - 1
                    else:
                        st.error("❌ Limit Reached (3/3). Please Upgrade.")
                
                # --- EXECUTE IF ALLOWED ---
                if allow_upload:
                    # 1. PROCESS
                    ist_time = datetime.utcnow() + timedelta(hours=5, minutes=30)
                    timestamp = ist_time.strftime("%Y-%m-%d %H:%M:%S")
                    file_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
                    
                    # 2. DISPLAY
                    st.success(f"✅ Secured at {timestamp}")
                    st.code(file_hash, language="text")
                    
                    # 3. THE COOL POLICY TEXT
                    st.info("⚡ **Zero-Trace Protocol:** Processed in RAM. Wiped in milliseconds. We protect the Hash, we destroy the File.")

                    # 4. CERTIFICATE
                    pdf_bytes = generate_certificate(st.session_state.user, uploaded_file.name, file_hash, timestamp)
                    
                    st.download_button(
                        label="📄 Download Official Certificate (PDF)",
                        data=pdf_bytes,
                        file_name=f"Certificate_{uploaded_file.name}.pdf",
                        mime="application/pdf",
                        type="secondary"
                    )
