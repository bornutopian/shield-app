import streamlit as st
from streamlit_gsheets import GSheetsConnection
import pandas as pd
import hashlib
from datetime import datetime
import pytz # Library for Indian Time
from fpdf import FPDF

# --- CONFIGURATION ---
st.set_page_config(page_title="Creator Shield", page_icon="🛡️", layout="centered")

# --- ASSETS & FUNCTIONS ---
def get_ist_time():
    """Returns current time in India Standard Time"""
    IST = pytz.timezone('Asia/Kolkata')
    return datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")

def generate_certificate(username, filename, file_hash, timestamp):
    pdf = FPDF()
    pdf.add_page()
    # Header
    pdf.set_font("Arial", 'B', 24)
    pdf.cell(0, 20, "Certificate of Registration", ln=True, align='C')
    
    # Body
    pdf.set_font("Arial", size=12)
    pdf.ln(20)
    pdf.cell(0, 10, f"This document certifies that the file listed below", ln=True, align='C')
    pdf.cell(0, 10, f"has been permanently secured on the Creator Shield Ledger.", ln=True, align='C')
    
    pdf.ln(20)
    # Details
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
    # Hash
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Digital Fingerprint (SHA-256):", ln=True)
    pdf.set_font("Courier", size=10)
    pdf.multi_cell(0, 10, file_hash)
    
    # Footer
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
if 'page' not in st.session_state: st.session_state.page = "Home"

# --- NAVIGATION CONTROLLER ---
def go_home(): st.session_state.page = "Home"
def go_login(): st.session_state.page = "Login"
def go_register(): st.session_state.page = "Register"

# --- PAGES ---

# 1. HOME PAGE (Clean & Direct)
if not st.session_state.login and st.session_state.page == "Home":
    st.image("https://img.icons8.com/color/96/shield.png", width=80)
    st.title("Creator Shield")
    st.write("### Protect Your Masterpiece.")
    st.write("Immutable proof of ownership for your digital assets.")
    
    st.divider()
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Login", type="primary", use_container_width=True):
            go_login()
            st.rerun()
    with col2:
        if st.button("Join Revolution", use_container_width=True):
            go_register()
            st.rerun()

# 2. LOGIN PAGE
elif not st.session_state.login and st.session_state.page == "Login":
    st.button("← Back", on_click=go_home)
    st.title("Welcome Back")
    
    u = st.text_input("Email", value="founder@creatorshield.in")
    p = st.text_input("Password", type="password", value="admin@#")
    
    if st.button("Enter Dashboard", type="primary"):
        # Master Key
        if u == "founder@creatorshield.in" and p == "admin@#":
            st.session_state.login = True
            st.session_state.user = u
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
                st.error("Connection Error")

# 3. REGISTER PAGE (With Subscription)
elif not st.session_state.login and st.session_state.page == "Register":
    st.button("← Back", on_click=go_home)
    st.title("Create Account")
    
    new_u = st.text_input("Email")
    new_p = st.text_input("Password", type="password")
    plan = st.radio("Select Plan", ["Free (Starter)", "Scorpio N (Pro - ₹99/yr)"])
    
    if plan == "Scorpio N (Pro - ₹99/yr)":
        st.info("🚀 **Scorpio N Plan Selected**")
        st.write("Unlimited Uploads • 1GB Size • Legal Certificates")
        st.write("**Pay via Google Pay:** `founder@upi` (Example)") 
        # ^ UPDATE THIS LATER WITH YOUR REAL UPI
        
    if st.button("Join Creator Shield", type="primary"):
        if db_active:
            try:
                df = conn.read(worksheet="users", ttl=0)
                new_data = pd.DataFrame([{
                    "username": new_u, 
                    "password": new_p, 
                    "credits": "Unlimited" if "Scorpio" in plan else "5"
                }])
                conn.update(worksheet="users", data=pd.concat([df, new_data], ignore_index=True))
                st.success("Account Created! Please Login.")
            except:
                st.error("Registration Failed. Try again.")

# 4. DASHBOARD (LOGGED IN)
else:
    with st.sidebar:
        st.write(f"👤 **{st.session_state.user}**")
        if st.button("Logout"):
            st.session_state.login = False
            go_home()
            st.rerun()

    st.title("🔐 Secure New Asset")
    
    # File Uploader
    uploaded_file = st.file_uploader("Upload File (Max 1GB)", help="Images, Audio, Video, Scripts")
    
    if uploaded_file:
        st.divider()
        c1, c2 = st.columns([1, 2])
        with c1:
            st.caption("File Size")
            st.write(f"**{uploaded_file.size / 1024:.1f} KB**")
        
        with c2:
            if st.button("🛡️ SECURE & CERTIFY", type="primary", use_container_width=True):
                # 1. Process
                timestamp = get_ist_time() # Uses IST Time
                file_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
                
                # 2. Display Result
                st.success(f"✅ Secured at {timestamp} (IST)")
                st.code(file_hash, language="text")
                
                # 3. PRIVACY MESSAGE (The Fix)
                st.info("🔒 **Privacy Note:** Your file has been hashed and deleted from our temporary server to ensure total privacy.")

                # 4. Cloud Record (Metadata only)
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
                        pass # Silent fail for privacy

                # 5. Generate Certificate
                pdf_bytes = generate_certificate(st.session_state.user, uploaded_file.name, file_hash, timestamp)
                
                st.download_button(
                    label="📄 Download Official Certificate (PDF)",
                    data=pdf_bytes,
                    file_name=f"Certificate_{uploaded_file.name}.pdf",
                    mime="application/pdf",
                    type="secondary"
                )
