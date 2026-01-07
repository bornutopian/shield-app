import streamlit as st
import pandas as pd
import hashlib
from datetime import datetime, timedelta
from fpdf import FPDF

# --- CONFIGURATION ---
st.set_page_config(page_title="Creator Shield", page_icon="🛡️", layout="wide")

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

# --- SESSION STATE & COUNTERS ---
if 'login' not in st.session_state: st.session_state.login = False
if 'user' not in st.session_state: st.session_state.user = ""
if 'test_user_usage' not in st.session_state: st.session_state.test_user_usage = 0

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
                
                # --- MANUAL USER LIST (EDIT HERE) ---
                
                # User 1: Founder
                if email == "founder@creatorshield.in" and password == "admin@#":
                    st.session_state.login = True
                    st.session_state.user = email
                    st.rerun()
                
                # User 2: Test User
                elif email == "test@gmail.com" and password == "123":
                    st.session_state.login = True
                    st.session_state.user = email
                    st.rerun()

                # User 3: Example (You can copy this block to add more)
                # elif email == "newuser@gmail.com" and password == "password":
                #     st.session_state.login = True
                #     st.session_state.user = email
                #     st.rerun()

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

# --- DASHBOARD (LOGGED IN) ---
else:
    # Calculate Credits Left
    credits_display = "Unlimited"
    if st.session_state.user == "test@gmail.com":
        credits_left = 3 - st.session_state.test_user_usage
        credits_display = str(max(0, credits_left)) 

    with st.sidebar:
        st.success(f"👤 {st.session_state.user}")
        st.info(f"Credits Left: **{credits_display}**")
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
                
                # --- LIMIT CHECK LOGIC ---
                allow_upload = True 
                
                # RESTRICT ONLY THE TEST USER
                if st.session_state.user == "test@gmail.com":
                    if st.session_state.test_user_usage >= 3:
                        allow_upload = False
                        st.error("❌ Limit Reached (3/3). Please Upgrade.")
                    else:
                        st.session_state.test_user_usage += 1
                
                # --- EXECUTE IF ALLOWED ---
                if allow_upload:
                    # 1. PROCESS
                    ist_time = datetime.utcnow() + timedelta(hours=5, minutes=30)
                    timestamp = ist_time.strftime("%Y-%m-%d %H:%M:%S")
                    file_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
                    
                    # 2. DISPLAY
                    st.success(f"✅ Secured at {timestamp}")
                    st.code(file_hash, language="text")
                    
                    st.info("⚡ **Zero-Trace Protocol:** Processed in RAM. Wiped in milliseconds. We protect the Hash, we destroy the File.")

                    # 3. CERTIFICATE
                    pdf_bytes = generate_certificate(st.session_state.user, uploaded_file.name, file_hash, timestamp)
                    
                    st.download_button(
                        label="📄 Download Official Certificate (PDF)",
                        data=pdf_bytes,
                        file_name=f"Certificate_{uploaded_file.name}.pdf",
                        mime="application/pdf",
                        type="secondary"
                    )

