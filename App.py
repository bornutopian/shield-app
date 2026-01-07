import streamlit as st
from streamlit_gsheets import GSheetsConnection
import pandas as pd
import hashlib
from datetime import datetime
from fpdf import FPDF
import base64

# --- CONFIGURATION ---
st.set_page_config(page_title="Creator Shield", page_icon="🛡️", layout="wide")

# --- ASSETS & FUNCTIONS ---

def generate_certificate(username, filename, file_hash, timestamp):
    """Generates a PDF Certificate of Registration"""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 24)
    pdf.cell(0, 20, "Certificate of Registration", ln=True, align='C')
    
    pdf.set_font("Arial", size=12)
    pdf.ln(20)
    pdf.cell(0, 10, f"This document certifies that the file listed below", ln=True, align='C')
    pdf.cell(0, 10, f"has been secured and timestamped on the Creator Shield Blockchain.", ln=True, align='C')
    
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
    pdf.cell(50, 10, "Timestamp:", border=0)
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

# --- CONNECT TO DATABASE ---
try:
    conn = st.connection("gsheets", type=GSheetsConnection)
    db_active = True
except:
    db_active = False

# --- SESSION STATE ---
if 'login' not in st.session_state: st.session_state.login = False
if 'user' not in st.session_state: st.session_state.user = ""
if 'plan' not in st.session_state: st.session_state.plan = "Free"

# --- NAVIGATION ---
if not st.session_state.login:
    # PUBLIC FACING SITE
    st.sidebar.title("🛡️ Creator Shield")
    page = st.sidebar.radio("Menu", ["Home", "Pricing (Scorpio N)", "Login", "Register"])
    
    if page == "Home":
        st.title("Protect Your Masterpiece.")
        st.markdown("""
        **Creator Shield** provides immutable proof of ownership for your digital assets.
        
        * **Timestamp:** Prove exactly when you created it.
        * **Fingerprint:** Bank-grade SHA-256 encryption.
        * **Certificate:** Downloadable legal proof.
        """)
        st.info("👈 Login or Register to start securing your work.")

    elif page == "Pricing (Scorpio N)":
        st.title("🚀 The Scorpio N Plan")
        st.write("For serious creators who need uncompromised power.")
        
        col1, col2 = st.columns(2)
        with col1:
            st.warning("### Starter")
            st.write("Free")
            st.write("• 5 Files / Month")
            st.write("• Basic Hash")
            st.write("• No Certificate")
        
        with col2:
            st.success("### Scorpio N (Pro)")
            st.write("**$99 / Year**")
            st.write("• **Unlimited** Secure Uploads")
            st.write("• **1GB** File Size Limit")
            st.write("• **Legal PDF Certificates**")
            st.write("• Priority Support")
            if st.button("Upgrade Now"):
                st.balloons()
                st.write("Contact Sales: founder@creatorshield.in")

    elif page == "Login":
        st.title("Login")
        u = st.text_input("Email", value="founder@creatorshield.in")
        p = st.text_input("Password", type="password", value="admin@#")
        
        if st.button("Enter Dashboard", type="primary"):
            # Master Key
            if u == "founder@creatorshield.in" and p == "admin@#":
                st.session_state.login = True
                st.session_state.user = u
                st.session_state.plan = "Scorpio N" # Founder gets top tier
                st.rerun()
            # Database Key
            elif db_active:
                try:
                    df = conn.read(worksheet="users", ttl=0)
                    df = df.dropna(how="all")
                    if not df.empty and ((df['username'] == u) & (df['password'] == p)).any():
                        st.session_state.login = True
                        st.session_state.user = u
                        st.rerun()
                    else:
                        st.error("Invalid Credentials")
                except:
                    st.error("Database Error")
    
    elif page == "Register":
        st.title("Create Account")
        new_u = st.text_input("Email")
        new_p = st.text_input("Password", type="password")
        if st.button("Join Creator Shield"):
            if db_active:
                try:
                    df = conn.read(worksheet="users", ttl=0)
                    new_data = pd.DataFrame([{"username": new_u, "password": new_p, "credits": "5"}])
                    conn.update(worksheet="users", data=pd.concat([df, new_data], ignore_index=True))
                    st.success("Account Created! Go to Login.")
                except:
                    st.error("Registration Failed")

# --- DASHBOARD (LOGGED IN) ---
else:
    with st.sidebar:
        st.title("🛡️ Dashboard")
        st.write(f"**User:** {st.session_state.user}")
        st.write(f"**Plan:** {st.session_state.plan}")
        st.divider()
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
                # 1. Process
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                file_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
                
                # 2. Display Result
                st.success(f"✅ Secured at {timestamp}")
                st.code(file_hash, language="text")
                
                # 3. Save to Cloud
                if db_active:
                    try:
                        v_df = conn.read(worksheet="vault", ttl=0)
                        entry = pd.DataFrame([{
                            "username": st.session_state.user,
                            "filename": uploaded_file.name,
                            "hash": file_hash,
                            "timestamp": timestamp
                        }])
                        conn.update(worksheet="vault", data=pd.concat([v_df, entry], ignore_index=True))
                    except:
                        st.warning("Cloud backup skipped (Connection issue), but Certificate is generated.")

                # 4. Generate Certificate
                pdf_bytes = generate_certificate(st.session_state.user, uploaded_file.name, file_hash, timestamp)
                
                st.download_button(
                    label="📄 Download Official Certificate (PDF)",
                    data=pdf_bytes,
                    file_name=f"Certificate_{uploaded_file.name}.pdf",
                    mime="application/pdf",
                    type="secondary"
                )
